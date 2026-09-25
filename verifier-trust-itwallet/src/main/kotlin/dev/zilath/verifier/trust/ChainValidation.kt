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
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.verifiesWithAnyAcceptableKey
import java.time.Duration
import java.time.Instant

/**
 * Validates a trust chain ordered leaf-first (OID-FED 1.0 §4 and §10.2, IT-Wallet §6.11):
 * its shape, each statement's signature top-down from the out-of-band anchor keys, their
 * temporal validity, and the superiors' directives on the leaf's metadata. Returns the
 * leaf's credential signing keys and the credential types it may issue.
 */
internal fun validateChain(
    chain: List<String>,
    expectedIssuer: String,
    rules: ChainRules,
): TrustDecision.Trusted {
    val statements = parseChain(chain, rules)
    val leaf = statements.first()
    val subordinates = subordinateStatementsOf(statements, expectedIssuer, rules.anchor)
    verifyTopDown(statements, rules)
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
    return TrustDecision.Trusted(credentialKeysOf(resolvedIssuer), credentialTypesOf(resolvedIssuer))
}

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
    rules: ChainRules,
) {
    val now = rules.clock.instant()
    var trustedKeys = rules.anchor.federationKeys
    for (index in statements.indices.reversed()) {
        val statement = statements[index]
        checkValidityWindow(statement, now)
        if (index > 0 && statement.issuer != statement.subject) checkLifetime(statement, rules.maxStatementLifetime)
        if (!verifiesWithAny(statement.jwt, listOf(keyNamedBy(statement, trustedKeys)))) {
            trustFail("the signature of the statement at chain position $index does not verify")
        }
        // Each statement attests the keys of the entity below it. One that carries none
        // used to inherit its superior's, which means a subordinate with an absent, empty
        // or malformed jwks silently kept the chain going under keys it never held. §3.2
        // requires the claim of every statement, the anchor's own configuration included,
        // although what that one publishes is not used.
        val attested =
            statement.federationJwks.ifEmpty {
                trustFail("the statement at chain position $index carries no federation keys")
            }
        // §10.2: the leaf's configuration must also validate with a key of its OWN jwks — the
        // one its kid names — not only with the key its superior attests.
        if (index == 0 && !verifiesWithAny(statement.jwt, listOf(keyNamedBy(statement, attested)))) {
            trustFail("the signature of the statement at chain position 0 does not verify")
        }
        if (index == 0 || statement.issuer != statement.subject) trustedKeys = attested
    }
}

/**
 * The anchor's entity configuration, fetched while resolving a chain online, checked with
 * the configured keys BEFORE its `federation_fetch_endpoint` is used.
 *
 * An intermediate's configuration cannot be verified at that point — its keys come from
 * the statement about it, fetched next — but the anchor's keys are known out-of-band. It
 * used to be taken as served: whoever could answer for the anchor's well-known URL (a
 * proxying fetcher, an interposed name or certificate) pointed the library at a fetch
 * endpoint of their choosing, and the forgery surfaced only when the statement from there
 * failed to verify, after the request had been made.
 */
internal fun requireGenuineAnchorConfiguration(
    configuration: EntityStatement,
    rules: ChainRules,
) {
    checkValidityWindow(configuration, rules.clock.instant())
    if (!verifiesWithAny(configuration.jwt, listOf(keyNamedBy(configuration, rules.anchor.federationKeys)))) {
        trustFail("the trust anchor's entity configuration does not verify with the configured keys")
    }
}

/**
 * OID-FED 1.0 §3: an entity statement "MUST include the kid (Key ID) header parameter",
 * and §3.2: it MUST exactly match the `kid` of a key in the set that verifies it. Every
 * trusted key used to be tried in turn, with no `kid` at all or with one naming a key the
 * set does not have. Harmless while every key in the set is attested by the superior, but a
 * rollover or historical-keys mechanism indexed by `kid` would have inherited the
 * ambiguity; now the statement is verified with the one key its `kid` names.
 */
internal fun keyNamedBy(
    statement: EntityStatement,
    trustedKeys: List<JWK>,
): JWK {
    val kid =
        statement.jwt.header.keyID
            ?.takeIf { it.isNotEmpty() } ?: trustFail("an entity statement has no kid")
    return trustedKeys.singleOrNull { it.keyID == kid } ?: trustFail("no trusted key matches an entity statement's kid")
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
        trustFail("an entity statement is not yet valid")
    }
    if (!now.minus(CLOCK_SKEW).isBefore(statement.expiresAt)) {
        trustFail("an entity statement is expired")
    }
}

/**
 * IT-Wallet 1.4.6 §6.11.1: a revocation must propagate within 24 hours, so a trust chain
 * must not be valid for longer — and a chain is valid until its earliest statement
 * expires. The cap is what bounds revocation latency: a superior withdraws an entity by no
 * longer serving its statement, and a copy that stays valid for a year keeps the entity
 * trusted for a year wherever the copy is replayed. Subordinate statements only — an entity
 * configuration is the entity's own and the production issuer's lives 365 days.
 */
private fun checkLifetime(
    statement: EntityStatement,
    maxLifetime: Duration,
) {
    if (Duration.between(statement.issuedAt, statement.expiresAt) > maxLifetime) {
        trustFail("a subordinate statement is valid for longer than the configured maximum")
    }
}

@OptIn(InternalZilathApi::class)
internal fun verifiesWithAny(
    jwt: SignedJWT,
    keys: List<JWK>,
): Boolean = verifiesWithAnyAcceptableKey(jwt, keys)
