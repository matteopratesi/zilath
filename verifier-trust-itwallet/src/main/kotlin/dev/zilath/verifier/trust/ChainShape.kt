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

/*
 * What a trust chain is made of, and where each statement may sit (OID-FED 1.0 §4, §3.2):
 * everything about a chain that can be checked before any signature or fetch.
 */

/** Parses [chain] and checks its shape, as [ProvidedChain] describes. */
internal fun providedChainOf(
    chain: List<String>,
    expectedIssuer: String,
    rules: ChainRules,
): ProvidedChain {
    val statements = parseChain(chain, rules)
    return ProvidedChain(statements.first(), subordinateStatementsOf(statements, expectedIssuer, rules.anchor))
}

internal fun parseChain(
    chain: List<String>,
    rules: ChainRules,
): List<EntityStatement> {
    if (chain.size < 2) trustFail("a trust chain needs at least the leaf and an anchor statement")
    // The offline chain comes from an attacker-controlled header: bound it before any parsing.
    // The anchor's own configuration may close it (OID-FED §4) and does not count towards the
    // length, as online resolution never fetches it into the chain: the bound leaves room for
    // it, the check after parsing counts without it.
    if (chain.size - 1 > rules.maxChainLength) trustFail(chainTooLong(rules))
    val statements = chain.map(::parseStatement)
    val length = if (endsWithOwnConfiguration(statements)) statements.size - 1 else statements.size
    if (length > rules.maxChainLength) trustFail(chainTooLong(rules))
    return statements
}

private fun chainTooLong(rules: ChainRules) = "trust chain longer than ${rules.maxChainLength} statements"

/** A chain whose last element is an entity configuration: the anchor's own, OID-FED §4 allows. */
private fun endsWithOwnConfiguration(statements: List<EntityStatement>): Boolean =
    statements.size > 2 && statements.last().let { it.issuer == it.subject }

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
internal fun subordinateStatementsOf(
    statements: List<EntityStatement>,
    expectedIssuer: String,
    anchor: TrustAnchorConfig,
): List<EntityStatement> {
    val leaf = statements.first()
    checkEndsAndLinks(statements, expectedIssuer, anchor)
    val last = statements.last()
    val endsWithAnchorConfiguration = endsWithOwnConfiguration(statements)
    val subordinates = statements.subList(1, if (endsWithAnchorConfiguration) statements.size - 1 else statements.size)
    if (subordinates.any { it.issuer == it.subject }) {
        trustFail("a statement after the leaf is not a subordinate statement")
    }
    // OID-FED §17.1: a trust chain MUST NOT contain loops. [L, F about L, L about F, anchor
    // about L] links and verifies once L and an entity of its own vouch for each other, and
    // puts F's statement in the position whose metadata overrides the leaf's: whatever the
    // anchor imposed on L in its own statement was gone. Every entity appears once.
    val entities = listOf(leaf.subject) + subordinates.map { it.issuer }
    if (entities.toSet().size != entities.size) trustFail("a trust chain loops back to an entity it has passed")
    // §3.2: a subordinate statement's iss MUST be one of the authority_hints in its
    // subject's entity configuration, "otherwise, the Federation graph is not well-formed".
    // The chain carries only the leaf's configuration, so that is the one checked here;
    // online resolution follows the hints at every level by construction.
    if (subordinates.first().issuer !in leaf.authorityHints) {
        trustFail("the leaf's superior in the chain is not among its authority_hints")
    }
    checkClaimsBelongToTheirKind(listOfNotNull(leaf, last.takeIf { endsWithAnchorConfiguration }), subordinates)
    if (endsWithAnchorConfiguration) checkClosingAnchorConfiguration(last, statements.size - 1, anchor)
    return subordinates
}

/**
 * The leaf is self-issued and is the credential's issuer, the last issuer is the anchor,
 * and each statement is about the entity before it.
 */
private fun checkEndsAndLinks(
    statements: List<EntityStatement>,
    expectedIssuer: String,
    anchor: TrustAnchorConfig,
) {
    val leaf = statements.first()
    if (leaf.issuer != leaf.subject) trustFail("the leaf entity configuration is not self-issued")
    if (leaf.subject != expectedIssuer) {
        trustFail("credential iss does not match the trust chain leaf")
    }
    if (statements.last().issuer != anchor.entityId) trustFail("the chain does not end at the configured trust anchor")
    for (index in 1 until statements.size) {
        val expectedSubject = if (index == 1) leaf.subject else statements[index - 1].issuer
        if (statements[index].subject != expectedSubject) {
            trustFail("broken iss/sub linking at chain position $index")
        }
    }
}

/**
 * OID-FED §3.2: metadata_policy, metadata_policy_crit, constraints and source_endpoint
 * belong to subordinate statements only. In an entity configuration they are not ignored —
 * which is how the leaf's was treated — nor applied — which is how a trailing anchor
 * configuration's was: the statement is malformed.
 */
private fun checkClaimsBelongToTheirKind(
    configurations: List<EntityStatement>,
    subordinates: List<EntityStatement>,
) {
    configurations.forEach { configuration ->
        if (SUBORDINATE_ONLY_CLAIMS.any(configuration::hasClaim)) {
            trustFail("an entity configuration carries claims only a subordinate statement may")
        }
    }
    // And the other way round: authority hints and trust marks are an entity's own claims
    // about itself, which a superior's statement about it has no business carrying.
    subordinates.forEach { statement ->
        if (CONFIGURATION_ONLY_CLAIMS.any(statement::hasClaim)) {
            trustFail("a subordinate statement carries claims only an entity configuration may")
        }
    }
}

/**
 * The anchor's own configuration closing a chain (OID-FED §4: optional) carries nothing the
 * decision uses — the anchor's keys are the configured ones — and a refreshed chain leaves
 * it out. It is still held to what §3.2 and §10.2 ask of it, here, before anything is
 * fetched: a `jwks`, and a signature by the configured key its `kid` names.
 */
private fun checkClosingAnchorConfiguration(
    configuration: EntityStatement,
    position: Int,
    anchor: TrustAnchorConfig,
) {
    if (configuration.federationJwks.isEmpty()) {
        trustFail("the statement at chain position $position carries no federation keys")
    }
    if (!verifiesWithAny(configuration.jwt, listOf(keyNamedBy(configuration, anchor.federationKeys)))) {
        trustFail("the signature of the statement at chain position $position does not verify")
    }
}

/** OID-FED §3.2: "the Entity Statement MUST be a Subordinate Statement" when present. */
private val SUBORDINATE_ONLY_CLAIMS =
    listOf("metadata_policy", "metadata_policy_crit", "constraints", "source_endpoint")

/** OID-FED §3.2: "the Entity Statement MUST be an Entity Configuration" when present. */
private val CONFIGURATION_ONLY_CLAIMS =
    listOf("authority_hints", "trust_anchor_hints", "trust_marks", "trust_mark_issuers", "trust_mark_owners")
