/*
 * Copyright (C) 2026 Matteo Pratesi
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package dev.zilath.verifier.trust

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.InternalZilathApi
import dev.zilath.verifier.core.verifiesWithAnyAcceptableKey
import java.time.Clock
import java.time.Instant

/**
 * Validates a trust chain ordered leaf-first (OID-FED 1.0 §4 and §10.2, IT-Wallet §6.11):
 * its shape, each statement's signature top-down from the out-of-band anchor keys, their
 * temporal validity, and the superiors' directives on the leaf's metadata. Returns the
 * leaf's credential signing keys.
 */
internal fun validateChain(
    chain: List<String>,
    expectedIssuer: String?,
    anchor: TrustAnchorConfig,
    clock: Clock,
    maxChainLength: Int = DEFAULT_MAX_CHAIN_LENGTH,
): List<JWK> {
    if (chain.size < 2) trustFail("a trust chain needs at least the leaf and an anchor statement")
    // The offline chain comes from an attacker-controlled header: bound it before any parsing.
    if (chain.size > maxChainLength) trustFail("trust chain longer than $maxChainLength statements")
    val statements = chain.map(::parseStatement)
    val leaf = statements.first()
    val subordinates = subordinateStatementsOf(statements, expectedIssuer, anchor)
    verifyTopDown(statements, anchor, clock.instant())
    checkPathAndNamingConstraints(subordinates)
    // metadata_policy: superiors constrain the leaf metadata. The immediate
    // superior's statement metadata overrides the leaf's first, the entity types the
    // constraints do not allow are dropped, then the policies, merged anchor-first, are
    // applied. The credential keys come from the RESOLVED metadata, so a superior can
    // restrict or replace what the leaf advertises.
    val effectiveMetadata =
        withoutDisallowedEntityTypes(MetadataPolicy.overlay(leaf.metadata, subordinates.first().metadata), subordinates)
    val policies = subordinates.asReversed().mapNotNull { it.metadataPolicy }
    val criticalOperators = subordinates.flatMap { it.metadataPolicyCrit }.toSet()
    val resolvedMetadata = MetadataPolicy.resolve(effectiveMetadata, policies, criticalOperators)
    val resolvedIssuer = resolvedMetadata["openid_credential_issuer"] as? Map<*, *>
    // No fallback. Credential-signing keys come from the RESOLVED metadata or from nowhere.
    //
    // Falling back to the leaf's federation keys turned a metadata_policy that RESTRICTS
    // openid_credential_issuer.jwks into one that widens: policy removes the key set, the
    // fallback hands over a different, unconstrained one. A leaf that published no
    // openid_credential_issuer at all got the same gift. Federation keys sign entity
    // statements; credential keys sign credentials. The separation is the point.
    val credentialKeys = jwksOf(resolvedIssuer?.get("jwks") as? Map<*, *>)
    if (credentialKeys.isEmpty()) {
        trustFail("the resolved metadata advertises no credential signing keys")
    }
    return credentialKeys
}

/**
 * The shape OID-FED 1.0 §4 gives a trust chain, and the chain's subordinate statements,
 * the leaf's immediate superior first.
 *
 * ES[0] is the leaf's entity configuration; every statement after it is a subordinate
 * statement (`iss` != `sub`) about the entity before it; the chain closes with the
 * configured anchor's statement, optionally followed by the anchor's own entity
 * configuration. The fourth internal review found the middle rule missing: the chain
 * `[leaf, leaf, anchor's statement]` linked and verified, and made the leaf its own
 * "immediate superior" — the metadata the anchor imposed on it in its statement was
 * overlaid by the leaf's own and vanished, and a `metadata_policy` the leaf wrote into its
 * own configuration was applied as if a superior had.
 */
private fun subordinateStatementsOf(
    statements: List<EntityStatement>,
    expectedIssuer: String?,
    anchor: TrustAnchorConfig,
): List<EntityStatement> {
    val leaf = statements.first()
    if (leaf.issuer != leaf.subject) trustFail("the leaf entity configuration is not self-issued")
    if (expectedIssuer != null && leaf.subject != expectedIssuer) {
        trustFail("credential iss does not match the trust chain leaf")
    }
    val last = statements.last()
    if (last.issuer != anchor.entityId) trustFail("the chain does not end at the configured trust anchor")
    for (index in 1 until statements.size) {
        val expectedSubject = if (index == 1) leaf.subject else statements[index - 1].issuer
        if (statements[index].subject != expectedSubject) {
            trustFail("broken iss/sub linking at chain position $index")
        }
    }
    val endsWithAnchorConfiguration = statements.size > 2 && last.issuer == last.subject
    val subordinates = statements.subList(1, if (endsWithAnchorConfiguration) statements.size - 1 else statements.size)
    if (subordinates.any { it.issuer == it.subject }) {
        trustFail("a statement after the leaf is not a subordinate statement")
    }
    // OID-FED §3.2: metadata_policy, metadata_policy_crit and constraints belong to
    // subordinate statements only. In an entity configuration they are not ignored — which
    // is how the leaf's was treated — nor applied — which is how a trailing anchor
    // configuration's was: the statement is malformed.
    listOfNotNull(leaf, last.takeIf { endsWithAnchorConfiguration }).forEach { configuration ->
        if (SUPERIOR_DIRECTIVES.any(configuration::hasClaim)) {
            trustFail("an entity configuration carries claims only a subordinate statement may")
        }
    }
    return subordinates
}

private val SUPERIOR_DIRECTIVES = listOf("metadata_policy", "metadata_policy_crit", "constraints")

/**
 * Checks every statement's validity window and signature from the anchor down. Each
 * statement attests the federation keys of the entity below it, which verify the next.
 *
 * The anchor's own entity configuration, when it closes the chain, is verified with the
 * configured keys and so is the anchor's statement below it (§4: the out-of-band keys
 * verify both) — the keys the configuration publishes about itself never replace the ones
 * the integrator configured.
 */
private fun verifyTopDown(
    statements: List<EntityStatement>,
    anchor: TrustAnchorConfig,
    now: Instant,
) {
    var trustedKeys = anchor.federationKeys
    for (index in statements.indices.reversed()) {
        val statement = statements[index]
        checkValidityWindow(statement, now)
        if (!verifiesWithAny(statement.jwt, trustedKeys)) {
            trustFail("signature of the statement about ${statement.subject} does not verify")
        }
        if (index > 0 && statement.issuer == statement.subject) continue
        // Each statement attests the keys of the entity below it. One that carries none
        // used to inherit its superior's, which means a subordinate with an absent, empty
        // or malformed jwks silently kept the chain going under keys it never held.
        trustedKeys =
            statement.federationJwks.ifEmpty {
                trustFail("the statement about ${statement.subject} carries no federation keys")
            }
    }
}

/**
 * A minute of tolerance, the same the status list checker allows. With none, a superior
 * whose clock runs two seconds ahead makes its entire federation untrusted — every
 * credential under it rejected, which on this project means people turned away at a
 * counter for someone else's NTP drift.
 */
private fun checkValidityWindow(
    statement: EntityStatement,
    now: Instant,
) {
    if (now.plus(CLOCK_SKEW).isBefore(statement.issuedAt)) {
        trustFail("statement of ${statement.subject} not yet valid")
    }
    if (!now.minus(CLOCK_SKEW).isBefore(statement.expiresAt)) {
        trustFail("statement of ${statement.subject} is expired")
    }
}

@OptIn(InternalZilathApi::class)
private fun verifiesWithAny(
    jwt: SignedJWT,
    keys: List<JWK>,
): Boolean = verifiesWithAnyAcceptableKey(jwt, keys)
