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
package dev.varco.verifier.core

import com.nimbusds.jose.jwk.JWK

/**
 * Decides whether the issuer of a credential is trusted and, if so, with which keys.
 *
 * The IT-Wallet OpenID Federation implementation lands in `verifier-trust-itwallet` (M0.4);
 * until then callers provide static evaluators.
 */
fun interface TrustEvaluator {
    fun evaluate(issuerChain: IssuerTrustInput): TrustDecision
}

/** What a credential exposes about its issuer before any signature check. */
data class IssuerTrustInput(
    /** The `iss` claim of the issuer-signed JWT, if parseable. */
    val issuer: String?,
    /** The `kid` JWS header parameter, if present. */
    val keyId: String?,
    /** The `x5c` JWS header chain, base64-encoded DER certificates, outermost first. */
    val certificateChain: List<String>,
)

sealed interface TrustDecision {
    /** The issuer is trusted; its signature must verify against one of [issuerKeys]. */
    data class Trusted(
        val issuerKeys: List<JWK>,
    ) : TrustDecision

    data class Untrusted(
        val reason: String? = null,
    ) : TrustDecision
}
