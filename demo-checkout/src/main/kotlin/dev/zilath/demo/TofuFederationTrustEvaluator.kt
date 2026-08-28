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
package dev.zilath.demo

import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.IssuerTrustInput
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.TrustEvaluator
import dev.zilath.verifier.trust.FederationFetcher
import dev.zilath.verifier.trust.FederationTrustEvaluator
import dev.zilath.verifier.trust.TrustAnchorConfig
import java.time.Clock

/**
 * Trust-on-first-use wrapper for CONFORMANCE RUNS ONLY: the anchor federation keys
 * are read from the anchor's own entity configuration on first evaluation, then the
 * real [FederationTrustEvaluator] does the chain validation. The conformance tool's
 * local anchor regenerates its keys at every run, so nothing can be pinned up front.
 */
internal class TofuFederationTrustEvaluator(
    private val anchorId: String,
    private val fetcher: FederationFetcher,
    private val clock: Clock,
) : TrustEvaluator {
    @Volatile
    private var delegate: FederationTrustEvaluator? = null

    override fun evaluate(issuerChain: IssuerTrustInput): TrustDecision =
        runCatching { resolvedDelegate().evaluate(issuerChain) }
            .getOrElse { TrustDecision.Untrusted("cannot bootstrap the trust anchor: ${it.message}") }

    @Synchronized
    private fun resolvedDelegate(): FederationTrustEvaluator {
        delegate?.let { return it }
        val body = fetcher.fetch(anchorId.trimEnd('/') + "/.well-known/openid-federation")
        val claims = SignedJWT.parse(body).jwtClaimsSet
        val jwks = checkNotNull(claims.getJSONObjectClaim("jwks")) { "anchor configuration has no jwks" }
        val keys =
            parseJwks(
                com.nimbusds.jose.util.JSONObjectUtils
                    .toJSONString(jwks),
            )
        // The anchor may serve on localhost while identifying itself with its real entity id
        // (the conformance tool does): the chain must be validated against the latter.
        val entityId = claims.subject ?: anchorId
        val evaluator = FederationTrustEvaluator(TrustAnchorConfig(entityId, keys), fetcher, clock)
        delegate = evaluator
        return evaluator
    }
}
