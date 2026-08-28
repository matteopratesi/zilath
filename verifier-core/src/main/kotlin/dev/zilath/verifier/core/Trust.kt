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
package dev.zilath.verifier.core

import com.nimbusds.jose.jwk.JWK

/**
 * Decides whether the issuer of a credential is trusted and, if so, with which keys.
 *
 * The OpenID Federation implementation for the IT-Wallet profile is
 * `FederationTrustEvaluator` in `verifier-trust-itwallet`; a static evaluator pinning known
 * keys is a legitimate choice for tests and closed deployments.
 */
fun interface TrustEvaluator {
    /**
     * Returns whether the issuer described by [issuerChain] is trusted.
     *
     * Must not throw: an unreachable federation endpoint, a broken chain or a malformed
     * statement are all [TrustDecision.Untrusted], because from the caller's side they are
     * the same answer — this credential cannot be accepted right now.
     */
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
    /**
     * The `trust_chain` JWS header parameter (OpenID Federation, IT-Wallet offline
     * scenarios): entity statements from the leaf to the trust anchor, if present.
     */
    val trustChain: List<String> = emptyList(),
)

/** The verdict on an issuer. */
sealed interface TrustDecision {
    /**
     * The issuer is trusted; its signature must verify against one of [issuerKeys].
     *
     * These are the credential SIGNING keys, which are not necessarily the federation keys
     * that signed the entity statements: for the IT-Wallet profile they come from the
     * issuer's `openid_credential_issuer` metadata after the superiors' `metadata_policy`
     * has been applied, so a superior can restrict what the leaf advertises.
     */
    data class Trusted(
        val issuerKeys: List<JWK>,
    ) : TrustDecision

    /**
     * The issuer is not trusted, or trust could not be established. [reason] is for logs;
     * it distinguishes "chain does not reach the anchor" from "anchor unreachable", a
     * difference that matters when diagnosing but not when deciding.
     */
    data class Untrusted(
        val reason: String? = null,
    ) : TrustDecision
}
