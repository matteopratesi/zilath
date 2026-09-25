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
    /**
     * Validates [presentation] against [ctx] and reports the outcome.
     *
     * A credential that fails any check is NOT an error: it comes back as
     * [VerificationResult.Rejected] with a [RejectionReason]. Implementations throw only
     * when the pipeline itself breaks, and even then the flow layer maps it to
     * [RejectionReason.INTERNAL_ERROR] — so a caller never has to tell "invalid credential"
     * apart from "bug" by catching exceptions.
     *
     * Nothing is retained: the presentation, its disclosures and its key binding exist only
     * for the duration of the call.
     */
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
    /**
     * The credential types this request will accept, from the DCQL query's `vct_values`.
     * Empty means no check — see `checkCredentialType`. Non-empty is what makes "verified"
     * mean "verified the credential you asked for" rather than "verified some credential
     * this issuer signed".
     */
    val expectedVcts: Set<String> = emptySet(),
    /**
     * The claims this request asked for, from the DCQL Credential Query the presentation
     * answers. Null means no requirement.
     *
     * When present, a presentation that does not satisfy it is rejected with
     * [RejectionReason.QUERY_NOT_SATISFIED]: none of the combinations
     * [RequestedClaims.claimSets] allows (without `claim_sets`: all the claims) is
     * satisfied. A requested claim is satisfied when its path selects something in the
     * credential (OpenID4VP 1.0 §7) and, when it names [RequestedClaim.values], something
     * it selects equals one of them in type and value (§6.3). Issuer plaintext satisfies it
     * as well as a disclosure does. [VerificationResult.Verified.claims] then carries only
     * the requested paths that are present — for a claim with `values`, only the selected
     * elements that match, so a value outside them is never handed over — plus `iss` and
     * `vct`, and never the issuer envelope.
     *
     * Before the fourth internal review a presentation that disclosed nothing at all came
     * back Verified: OpenID4VP puts the duty on the wallet, but "verified" has to mean the
     * answer satisfies the question.
     */
    val requestedClaims: RequestedClaims? = null,
    /** Size limits checked before anything is parsed; see [PresentationLimits] for the defaults' reasoning. */
    val presentationLimits: PresentationLimits = PresentationLimits(),
) {
    init {
        require(expectedAudiences.isNotEmpty()) { "at least one expected audience is required" }
        require(expectedAudiences.none { it.isBlank() }) { "an expected audience must not be blank" }
    }

    companion object {
        val DEFAULT_KEY_BINDING_MAX_AGE: Duration = Duration.ofMinutes(5)
    }
}

/** The outcome of a single verification. Exhaustive: there is no third state. */
sealed interface VerificationResult {
    /**
     * Every check passed. [claims] is an allowlist: with [VerificationContext.requestedClaims],
     * the requested claims that are present; without, the claims the holder disclosed (a
     * disclosed member of a plaintext object keeps its container, not its plaintext
     * siblings). Plus `iss` and `vct` in both cases. Never the issuer envelope (`iat`, `exp`,
     * `nbf`, `jti`, `sub`, `aud`, `cnf`, `status`, `_sd_alg`), every member of which is stable
     * per credential and would let a consumer link two verifications of the same person, and
     * never an issuer plaintext claim nobody asked for.
     */
    data class Verified(
        val claims: DisclosedClaims,
    ) : VerificationResult

    /**
     * A check failed. [reason] is the stable, machine-readable outcome; [detail] is a
     * short human-readable hint for LOGS ONLY.
     *
     * Two rules for [detail], both deliberate: it is not meant for the person at the other
     * end, and every phrase `SdJwtVcCredentialVerifier` writes is a fixed one, never a claim
     * value or any part of the presentation. Telling a holder which check failed turns the
     * verifier into an oracle for probing credentials, and the surrounding UI has no need
     * for it — the answer the flow owes its caller is yes or no.
     *
     * One exception, for [RejectionReason.UNTRUSTED_ISSUER]: the detail is the
     * [TrustEvaluator]'s own [TrustDecision.Untrusted.reason], cut to 200 characters with
     * control characters and line separators replaced, but otherwise the evaluator's text.
     * An evaluator that puts something from the presentation in its reason puts it here.
     */
    data class Rejected(
        val reason: RejectionReason,
        val detail: String? = null,
    ) : VerificationResult
}

/**
 * The claims a verification hands over, with selective-disclosure digests resolved: see
 * [VerificationResult.Verified] for which.
 */
data class DisclosedClaims(
    val claims: JsonObject,
)

/**
 * Why a presentation was rejected.
 *
 * The set is deliberately coarse-grained and free of credential content: it exists to be
 * logged and counted, not to explain to a holder what to fix. Treat it as an open enum —
 * new members may be added as profiles grow, so handle the unknown case as a rejection.
 */
enum class RejectionReason {
    INVALID_ISSUER_SIGNATURE,
    UNTRUSTED_ISSUER,
    INVALID_KEY_BINDING,
    NONCE_MISMATCH,
    AUDIENCE_MISMATCH,
    EXPIRED,
    NOT_YET_VALID,
    REVOKED,

    /** The credential is suspended (status list value 0x02). */
    SUSPENDED,

    /** The credential's status is neither valid, revoked nor suspended (an application-specific value). */
    STATUS_NOT_VALID,
    STATUS_CHECK_FAILED,
    MALFORMED,
    DISCLOSURE_TAMPERED,
    UNSUPPORTED_FORMAT,

    /** The presentation does not answer what the request asked for: see [VerificationContext.requestedClaims]. */
    QUERY_NOT_SATISFIED,

    /** A wallet response arrived for a transaction whose nonce was already consumed. */
    REPLAY,

    /** The verification pipeline itself failed unexpectedly (infrastructure, not the credential). */
    INTERNAL_ERROR,
}
