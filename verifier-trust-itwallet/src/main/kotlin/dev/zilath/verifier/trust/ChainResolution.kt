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

import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/*
 * Online resolution: the documents of a chain, fetched through the integrator's
 * [FederationFetcher] and not yet validated — [validateChain] does that on the result.
 */

/**
 * Walks from [issuer]'s entity configuration up its `authority_hints` to the configured
 * anchor, collecting the subordinate statements on the way; returns the chain leaf-first.
 *
 * At each level the superior is the one [preferredSuperiors] names for it, when the fresh
 * configuration still lists it among its hints, and otherwise the first hint. A provided
 * `trust_chain` passes its own path here, so refreshing it follows the superiors the
 * issuer chose instead of whichever hint happens to come first; the fresh documents still
 * decide, a hint the entity no longer lists is not followed.
 */
internal fun resolveChain(
    fetcher: FederationFetcher,
    issuer: String,
    rules: ChainRules,
    preferredSuperiors: List<String> = emptyList(),
): List<String> {
    val statements = mutableListOf(fetchEntityConfiguration(fetcher, issuer))
    var current = statements.first()
    // OID-FED §10.1: an authority hint that leads back to an entity already on the path MUST
    // NOT be used. A provided chain steers this walk, so without it a leaf could lead the
    // refresh round a loop of its own making.
    val visited = mutableSetOf(issuer)
    while (current.issuer != rules.anchor.entityId) {
        if (statements.size >= rules.maxChainLength) {
            trustFail("trust chain longer than ${rules.maxChainLength} before reaching the anchor")
        }
        val hints = current.authorityHints.filter { it !in visited }
        val superior =
            preferredSuperiors.getOrNull(statements.size - 1)?.takeIf { it in hints }
                ?: hints.firstOrNull()
                ?: trustFail("no authority_hints leading to the trust anchor ${rules.anchor.entityId}")
        visited += superior
        val superiorConfiguration = fetchEntityConfiguration(fetcher, superior)
        if (superior == rules.anchor.entityId) requireGenuineAnchorConfiguration(superiorConfiguration, rules)
        statements += fetchSubordinateStatement(fetcher, superiorConfiguration, current.subject)
        current = superiorConfiguration
    }
    return statements.map { it.serialized }
}

internal fun fetchEntityConfiguration(
    fetcher: FederationFetcher,
    entityId: String,
): EntityStatement {
    requireUsableEntityId(entityId)
    val body = fetchDocument(fetcher, entityId.trimEnd('/') + WELL_KNOWN_FEDERATION, "an entity configuration")
    val statement = parseStatement(body)
    if (statement.issuer != entityId || statement.subject != entityId) {
        trustFail("a fetched entity configuration has mismatched iss/sub")
    }
    return statement
}

internal fun fetchSubordinateStatement(
    fetcher: FederationFetcher,
    superiorConfiguration: EntityStatement,
    subject: String,
): EntityStatement {
    val endpoint =
        superiorConfiguration.federationFetchEndpoint
            ?: trustFail("a superior exposes no federation_fetch_endpoint")
    requireUsableFetchEndpoint(endpoint)
    val separator = if ('?' in endpoint) '&' else '?'
    val url = "$endpoint${separator}sub=${URLEncoder.encode(subject, StandardCharsets.UTF_8)}"
    return parseStatement(fetchDocument(fetcher, url, "a subordinate statement"))
}

/**
 * [FederationDocumentNotFoundException] is the federation's answer — for a subordinate
 * statement, the way a superior withdraws, that is revokes, an entity — and fails the
 * chain like any other answer. Anything else the fetcher throws means no answer came
 * back: [FederationUnreachable]. [what] is one of this file's fixed phrases.
 */
private fun fetchDocument(
    fetcher: FederationFetcher,
    url: String,
    what: String,
): String =
    runCatching { fetcher.fetch(url) }.getOrElse { failure ->
        if (failure is FederationDocumentNotFoundException) trustFail("the federation does not publish $what")
        throw FederationUnreachable("cannot fetch $what")
    }
