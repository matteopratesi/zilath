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

import kotlinx.serialization.json.JsonObject
import java.time.Clock
import java.time.Duration

/**
 * Verifies a raw credential presentation and returns a minimal outcome.
 *
 * Implementations are stateless: nothing about the presentation is retained
 * after [verify] returns (project red line: verify, never store).
 */
interface CredentialVerifier {
    fun verify(
        presentation: RawPresentation,
        ctx: VerificationContext,
    ): VerificationResult
}

/** A credential presentation as received from the wallet, before any validation. */
sealed interface RawPresentation {
    /** An SD-JWT VC in compact serialization: `issuer-jwt~disclosure1~...~kb-jwt`. */
    data class SdJwtVcPresentation(
        val compactSerialization: String,
    ) : RawPresentation

    /** Placeholder for the v1 mdoc-CBOR format: declared so the public API stays stable. */
    data class MdocPresentation(
        val deviceResponseBase64Url: String,
    ) : RawPresentation
}

/** Everything the verifier needs to judge a single presentation. */
data class VerificationContext(
    /** The nonce this transaction challenged the wallet with. */
    val expectedNonce: String,
    /**
     * The relying party identifiers the key binding may be addressed to — normally one.
     * A set, because the specifications disagree on whether the audience carries the
     * Client Identifier Prefix (OpenID4VP 1.0 App. B.3.6 says it does and its example
     * shows it; the IT-Wallet rules say "Relying Party unique entity identifier", which
     * reads as the stripped form). Every entry must be a form of the SAME verifier:
     * accepting our own identifier written two ways binds the presentation to us exactly
     * as one entry would. Reported upstream: pagopa/wallet-conformance-test#221.
     */
    val expectedAudiences: Set<String>,
    val clock: Clock,
    val trustEvaluator: TrustEvaluator,
    val statusChecker: StatusChecker,
    /** Maximum accepted distance between the key binding `iat` and now, in both directions. */
    val keyBindingMaxAge: Duration = DEFAULT_KEY_BINDING_MAX_AGE,
) {
    init {
        require(expectedAudiences.isNotEmpty()) { "at least one expected audience is required" }
        require(expectedAudiences.none { it.isBlank() }) { "an expected audience must not be blank" }
    }

    companion object {
        val DEFAULT_KEY_BINDING_MAX_AGE: Duration = Duration.ofMinutes(5)
    }
}

sealed interface VerificationResult {
    data class Verified(
        val claims: DisclosedClaims,
    ) : VerificationResult

    data class Rejected(
        val reason: RejectionReason,
        val detail: String? = null,
    ) : VerificationResult
}

/** The claims actually disclosed by the holder, with selective-disclosure digests resolved. */
data class DisclosedClaims(
    val claims: JsonObject,
)

enum class RejectionReason {
    INVALID_ISSUER_SIGNATURE,
    UNTRUSTED_ISSUER,
    INVALID_KEY_BINDING,
    NONCE_MISMATCH,
    AUDIENCE_MISMATCH,
    EXPIRED,
    NOT_YET_VALID,
    REVOKED,
    STATUS_CHECK_FAILED,
    MALFORMED,
    DISCLOSURE_TAMPERED,
    UNSUPPORTED_FORMAT,

    /** A wallet response arrived for a transaction whose nonce was already consumed. */
    REPLAY,

    /** The verification pipeline itself failed unexpectedly (infrastructure, not the credential). */
    INTERNAL_ERROR,
}
