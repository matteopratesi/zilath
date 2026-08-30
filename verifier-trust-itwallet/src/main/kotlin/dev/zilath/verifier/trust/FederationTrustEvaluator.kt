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
import dev.zilath.verifier.core.IssuerTrustInput
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.TrustEvaluator
import java.time.Clock

/**
 * [TrustEvaluator] for the IT-Wallet OpenID Federation profile (spec v1.4.5 §6).
 *
 * Trust is anchored to [TrustAnchorConfig]: the anchor entity id and its federation
 * keys, obtained out-of-band (for the PoC: the conformance tool's local anchor).
 *
 * Evaluation order:
 * 1. If the credential carried a `trust_chain` JWS header (offline scenario), that
 *    chain is validated as provided.
 * 2. Otherwise the chain is resolved online: the leaf entity configuration from
 *    `{iss}/.well-known/openid-federation`, then subordinate statements walking
 *    `authority_hints` up to the configured anchor, via the injectable [FederationFetcher].
 *
 * On success the decision carries the keys the issuer signs credentials with:
 * the `jwks` of its `openid_credential_issuer` metadata AFTER applying the
 * `metadata_policy` of the superior statements (merged anchor-first, OID-FED §6.1),
 * falling back to the leaf's federation keys when that metadata carries no dedicated
 * set. A policy conflict or violation fails the evaluation.
 */
class FederationTrustEvaluator(
    private val anchor: TrustAnchorConfig,
    private val fetcher: FederationFetcher,
    private val clock: Clock,
    private val maxChainLength: Int = DEFAULT_MAX_CHAIN_LENGTH,
) : TrustEvaluator {
    override fun evaluate(issuerChain: IssuerTrustInput): TrustDecision =
        runCatching {
            val chain =
                if (issuerChain.trustChain.isNotEmpty()) {
                    issuerChain.trustChain
                } else {
                    resolveChain(issuerChain.issuer ?: trustFail("credential has no iss claim"))
                }
            TrustDecision.Trusted(validateChain(chain, issuerChain.issuer, anchor, clock, maxChainLength))
        }.getOrElse { failure ->
            when (failure) {
                is TrustFailure -> TrustDecision.Untrusted(failure.message)
                else -> TrustDecision.Untrusted("trust evaluation failed: ${failure.message}")
            }
        }

    private fun resolveChain(issuer: String): List<String> {
        val statements = mutableListOf(fetchEntityConfiguration(fetcher, issuer))
        var current = statements.first()
        while (current.issuer != anchor.entityId) {
            if (statements.size >= maxChainLength) {
                trustFail("trust chain longer than $maxChainLength before reaching the anchor")
            }
            val superior =
                current.authorityHints.firstOrNull()
                    ?: trustFail("no authority_hints leading to the trust anchor ${anchor.entityId}")
            val superiorConfiguration = fetchEntityConfiguration(fetcher, superior)
            statements += fetchSubordinateStatement(fetcher, superiorConfiguration, current.subject)
            current = superiorConfiguration
        }
        return statements.map { it.serialized }
    }
}

/** The trust anchor identity and federation keys, obtained out-of-band. */
data class TrustAnchorConfig(
    val entityId: String,
    val federationKeys: List<JWK>,
) {
    init {
        require(federationKeys.isNotEmpty()) { "the trust anchor needs at least one federation key" }
    }
}

/**
 * Retrieves federation documents over HTTP; injectable so tests stay offline.
 *
 * SECURITY: every [url] derives from content an attacker may influence — the `iss` of a
 * credential nobody has verified yet, `authority_hints` and `federation_fetch_endpoint`
 * values from documents that are only verified once the chain closes at the anchor. The
 * library enforces their shape — https with a hostname, no userinfo, no IP literals —
 * with one exception: the exact loopback names (localhost, 127.0.0.1, [::1]) are also
 * accepted as plain http or as literals, so local development needs no TLS. It never
 * resolves names, so the network boundary is this implementation's job: set aggressive
 * timeouts, cap the response size, refuse redirects or re-check each redirect target
 * against the same rules — and when the deployment has an internal network to protect,
 * refuse destinations that resolve into it.
 */
fun interface FederationFetcher {
    /** Returns the response body for [url], or throws on any transport error. */
    fun fetch(url: String): String
}
