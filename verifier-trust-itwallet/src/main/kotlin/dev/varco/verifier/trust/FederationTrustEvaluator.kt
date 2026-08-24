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
package dev.varco.verifier.trust

import com.nimbusds.jose.jwk.JWK
import dev.varco.verifier.core.IssuerTrustInput
import dev.varco.verifier.core.TrustDecision
import dev.varco.verifier.core.TrustEvaluator
import java.time.Clock

/**
 * [TrustEvaluator] for the IT-Wallet OpenID Federation profile (spec v1.4.5 §6,
 * plan docs/03 §5-M0.4).
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
 * the `jwks` of its `openid_credential_issuer` metadata, falling back to the leaf's
 * federation keys when that metadata carries no dedicated set.
 *
 * Known gap (tracked): `metadata_policy` operators from subordinate statements are
 * NOT applied yet; policies constraining issuer metadata are ignored.
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
            TrustDecision.Trusted(validateChain(chain, issuerChain.issuer, anchor, clock))
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

    companion object {
        private const val DEFAULT_MAX_CHAIN_LENGTH = 4
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

/** Retrieves federation documents over HTTP; injectable so tests stay offline. */
fun interface FederationFetcher {
    /** Returns the response body for [url], or throws on any transport error. */
    fun fetch(url: String): String
}
