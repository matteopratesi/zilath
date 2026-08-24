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
    /** The relying party identifier the key binding must be addressed to. */
    val expectedAudience: String,
    val clock: Clock,
    val trustEvaluator: TrustEvaluator,
    val statusChecker: StatusChecker,
    /** Maximum accepted distance between the key binding `iat` and now, in both directions. */
    val keyBindingMaxAge: Duration = DEFAULT_KEY_BINDING_MAX_AGE,
) {
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
}
