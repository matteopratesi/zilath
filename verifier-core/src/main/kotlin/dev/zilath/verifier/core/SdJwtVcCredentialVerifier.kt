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

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import eu.europa.ec.eudi.sdjwt.SdJwtAndKbJwt
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import java.time.Duration

/**
 * Rejects a JWT whose `typ` header contradicts what it is being used as.
 *
 * Deliberately lenient about ABSENCE. The specification requires `typ`, but our own test
 * vectors do not set it and there is no evidence yet about what the production IT-Wallet
 * issuer emits — and on this project rejecting a genuine credential is as bad as accepting
 * a forged one. Checking only what is present costs no false rejection and still stops the
 * cheap version of the attack: presenting some other JWT that the issuer signed with the
 * same key, which will normally carry a `typ` of its own.
 */
@OptIn(InternalZilathApi::class)
private fun checkTypIfPresent(
    header: JWSHeader,
    accepted: Set<String>,
    reason: RejectionReason,
) {
    val typ = header.type?.toString() ?: return
    if (accepted.none { mediaTypeMatches(typ, it) }) reject(reason, "unexpected typ header")
}

/**
 * Verifies SD-JWT VC presentations (issuer JWT + selective disclosures + key binding JWT)
 * against the full set of checks required for a presentation to be accepted:
 * issuer signature via [TrustEvaluator], disclosure integrity, key binding
 * (signature with the `cnf` key, audience, nonce, freshness, `sd_hash`),
 * temporal validity against the injected clock, and revocation via [StatusChecker].
 *
 * Cryptography and SD-JWT processing are delegated to Nimbus JOSE+JWT and the
 * EUDI `eudi-lib-jvm-sdjwt-kt` library; this class only orchestrates and maps
 * failures to stable [RejectionReason]s.
 */

class SdJwtVcCredentialVerifier : CredentialVerifier {
    override fun verify(
        presentation: RawPresentation,
        ctx: VerificationContext,
    ): VerificationResult =
        try {
            when (presentation) {
                is RawPresentation.SdJwtVcPresentation -> doVerify(presentation.compactSerialization, ctx)
                is RawPresentation.MdocPresentation ->
                    reject(RejectionReason.UNSUPPORTED_FORMAT, "mdoc-CBOR is a v1 target")
            }
        } catch (rejection: SdJwtRejection) {
            VerificationResult.Rejected(rejection.reason, rejection.detail)
        }

    private fun doVerify(
        compact: String,
        ctx: VerificationContext,
    ): VerificationResult.Verified {
        val issuerJwt = parseIssuerJwt(compact)
        checkTypIfPresent(issuerJwt.header, ISSUER_JWT_TYPS, RejectionReason.UNSUPPORTED_FORMAT)
        val trusted = trustedIssuer(issuerJwt, ctx)
        val issuerKeys = trusted.issuerKeys
        val verified = verifyWithEudiLibrary(compact, issuerKeys)
        val issuerClaims = verified.sdJwt.jwt.jwtClaimsSet
        checkIssuerAuthorisedForType(issuerClaims, trusted)
        checkCredentialType(issuerClaims, ctx)
        checkTemporalValidity(verified.sdJwt.jwt, ctx)
        checkTypIfPresent(verified.keyBindingJwt.header, KEY_BINDING_TYPS, RejectionReason.INVALID_KEY_BINDING)
        checkKeyBinding(verified.keyBindingJwt, ctx)
        checkStatus(issuerClaims, issuerKeys, ctx)
        val claims = with(NimbusSdJwtOps) { verified.sdJwt.recreateClaims(null) }
        return VerificationResult.Verified(DisclosedClaims(withoutInternalClaims(claims)))
    }

    private fun trustedIssuer(
        issuerJwt: SignedJWT,
        ctx: VerificationContext,
    ): TrustDecision.Trusted =
        when (val decision = ctx.trustEvaluator.evaluate(trustInputOf(issuerJwt))) {
            is TrustDecision.Trusted ->
                decision.also {
                    if (it.issuerKeys.isEmpty()) reject(RejectionReason.UNTRUSTED_ISSUER, "no trusted issuer keys")
                }
            is TrustDecision.Untrusted -> reject(RejectionReason.UNTRUSTED_ISSUER, decision.reason)
        }

    private fun verifyWithEudiLibrary(
        compact: String,
        issuerKeys: List<com.nimbusds.jose.jwk.JWK>,
    ): SdJwtAndKbJwt<SignedJWT> =
        runBlocking {
            NimbusSdJwtOps.verify(issuerSignatureVerifier(issuerKeys), holderKeyBindingVerifier(), compact)
        }.getOrElse { failure -> throw rejectionOf(failure) }

    /**
     * The credential must be of the type that was asked for.
     *
     * The wallet chooses which credential to present, so without this a holder — or a
     * malicious wallet — can answer a request for one credential with a different one from
     * the same trusted issuer, and the library would report it verified. "Verified" has to
     * mean "verified the thing you asked for".
     *
     * No expected types configured means no check: a caller building its own DCQL query
     * that does not constrain `vct_values` gets the old behaviour rather than a surprise
     * rejection.
     */
    private fun checkCredentialType(
        issuerClaims: JWTClaimsSet,
        ctx: VerificationContext,
    ) {
        if (ctx.expectedVcts.isEmpty()) return
        val vct = runCatching { issuerClaims.getStringClaim("vct") }.getOrNull()
        if (vct == null || vct !in ctx.expectedVcts) {
            reject(RejectionReason.UNSUPPORTED_FORMAT, "credential type is not the one requested")
        }
    }

    /**
     * `exp` is required and must be a plausible date; `nbf` is checked when present. Both are
     * read as numbers from the signed payload ([numericDateClaim]), not through Nimbus's
     * `Date`, whose seconds-to-milliseconds conversion wraps around silently.
     *
     * A credential without `exp` used to verify for ever: SD-JWT VC leaves the claim
     * optional, but IT-Wallet 1.4.6 makes it mandatory in the credential data model, and a
     * profile-conformant issuer never omits it. The commoner issuer bug, a timestamp in
     * milliseconds, reads as a year beyond 9999 and is no NumericDate at all; the ceiling
     * refuses whatever else would make a credential outlive its holder — fifty years is far
     * beyond any credential's validity and still short of the absurd.
     *
     * `detail` is retained on the transaction and reaches the application log, so it carries
     * no value taken from the credential — not even a timestamp. The reason code says what
     * failed; the exact instant is the holder's, not the log's.
     */
    private fun checkTemporalValidity(
        issuerJwt: SignedJWT,
        ctx: VerificationContext,
    ) {
        val now = ctx.clock.instant()
        val payload = issuerJwt.payload.toJSONObject()
        val expiration =
            when (val exp = numericDateClaim(payload, "exp")) {
                NumericDateClaim.Absent -> reject(RejectionReason.MALFORMED, "credential has no exp")
                NumericDateClaim.Invalid -> reject(RejectionReason.MALFORMED, "credential exp is not a plausible date")
                is NumericDateClaim.At -> exp.instant
            }
        if (expiration.isAfter(now.plus(MAX_EXP_AHEAD))) {
            reject(RejectionReason.MALFORMED, "credential exp is not a plausible date")
        }
        if (!expiration.isAfter(now.minus(CLOCK_SKEW))) {
            reject(RejectionReason.EXPIRED, "credential is expired")
        }
        val notBefore =
            when (val nbf = numericDateClaim(payload, "nbf")) {
                NumericDateClaim.Absent -> null
                NumericDateClaim.Invalid -> reject(RejectionReason.MALFORMED, "credential nbf is not a plausible date")
                is NumericDateClaim.At -> nbf.instant
            }
        if (notBefore != null && notBefore.isAfter(now.plus(CLOCK_SKEW))) {
            reject(RejectionReason.NOT_YET_VALID, "credential is not yet valid")
        }
    }

    /**
     * Audience, nonce and freshness. The key binding's signature under the `cnf` key and its
     * `sd_hash` are checked by the EUDI library before this runs (`MustBePresentAndValid`),
     * with the digest `_sd_alg` names, as RFC 9901 §4.3 requires. Zilath used to recompute
     * `sd_hash` in SHA-256 whatever `_sd_alg` said: redundant for SHA-256, and for an issuer
     * using sha-384 or sha-512 a rejection of every genuine presentation, blamed on the
     * wallet (fourth internal review).
     *
     * Exactly one audience. RFC 9901 §4.3 says `aud` MUST be a single string, and IT-Wallet
     * 1.4.6 that it MUST match the relying party's identifier; a list that names us beside
     * someone else was accepted. A one-element array naming us is accepted: Nimbus reads
     * both forms as the same list, and the array names the same single receiver the string
     * would — nothing is bound differently, and refusing it would only turn a wallet's
     * serialisation habit into a denial.
     */
    private fun checkKeyBinding(
        kbJwt: SignedJWT,
        ctx: VerificationContext,
    ) {
        val kbClaims = kbJwt.jwtClaimsSet
        val audience = kbClaims.audience.orEmpty()
        if (audience.size != 1 || audience.single() !in ctx.expectedAudiences) {
            reject(RejectionReason.AUDIENCE_MISMATCH, "key binding not addressed to this verifier")
        }
        val nonce = runCatching { kbClaims.getStringClaim("nonce") }.getOrNull()
        if (nonce != ctx.expectedNonce) {
            reject(RejectionReason.NONCE_MISMATCH, "key binding nonce does not match the transaction")
        }
        checkKeyBindingFreshness(kbJwt, ctx)
    }

    /** An `iat` outside the representable range is, a fortiori, outside the window. */
    private fun checkKeyBindingFreshness(
        kbJwt: SignedJWT,
        ctx: VerificationContext,
    ) {
        val issuedAt =
            when (val iat = numericDateClaim(kbJwt.payload.toJSONObject(), "iat")) {
                NumericDateClaim.Absent -> reject(RejectionReason.INVALID_KEY_BINDING, "key binding has no iat")
                NumericDateClaim.Invalid ->
                    reject(RejectionReason.INVALID_KEY_BINDING, "key binding iat outside the accepted window")
                is NumericDateClaim.At -> iat.instant
            }
        val distance = Duration.between(issuedAt, ctx.clock.instant()).abs()
        if (distance > ctx.keyBindingMaxAge) {
            reject(RejectionReason.INVALID_KEY_BINDING, "key binding iat outside the accepted window")
        }
    }

    /**
     * Strips the issuer envelope, keeping what the holder disclosed plus the two envelope
     * claims that say WHAT was verified without saying WHICH copy.
     *
     * `recreateClaims` returns the whole issuer-signed payload, not only what the holder chose
     * to disclose. Most of that envelope is stable per credential: `cnf` (the holder key),
     * `status` (the index in the issuer's revocation list), and just as much `iat`, `exp`,
     * `nbf`, `jti`, `sub` — an issuance instant at second granularity, together with `iss` and
     * `vct`, singles out one credential almost as surely as a serial number would. Handing any
     * of them over would let an integrator, or anything downstream, link two verifications of
     * the same person across venues and across months. The third internal review found that
     * only `cnf` and `status` were being removed.
     *
     * `iss` and `vct` stay: they name the issuer and the credential type, are identical for
     * every holder of that type, and are what an application needs to know what it verified.
     *
     * **This is a blocklist, and a blocklist is not a guarantee.** It removes the envelope
     * this specification defines; a claim the ISSUER chose to put in the credential
     * unprotected — outside selective disclosure, under a name of its own invention — is
     * neither disclosed by the holder nor listed here, and it survives. Nothing in the
     * verifier can tell such a claim from a legitimate always-visible attribute. The
     * airtight form is an allowlist of the names the holder actually disclosed, which means
     * telling disclosed claims apart from the issuer's plaintext ones: computable as the
     * difference between the recreated claims and the issuer JWT payload, except that a
     * plaintext object with selectively disclosed members inside it would then lose them.
     * Getting that right needs the nested case covered by tests against a real issuer, so
     * it is recorded as a known limit (docs/privacy-by-design.md) rather than guessed at
     * here. Raised by automated review on this pull request.
     */
    private fun withoutInternalClaims(claims: JsonObject): JsonObject =
        JsonObject(claims.filterKeys { it !in ENVELOPE_CLAIMS })

    private fun checkStatus(
        issuerClaims: JWTClaimsSet,
        issuerKeys: List<JWK>,
        ctx: VerificationContext,
    ) {
        val statusRef = statusReferenceOf(issuerClaims) ?: return
        val trust = StatusIssuerTrust(issuerClaims.issuer, issuerKeys)
        when (ctx.statusChecker.check(statusRef, trust)) {
            CredentialStatus.VALID -> Unit
            CredentialStatus.REVOKED -> reject(RejectionReason.REVOKED, "credential is revoked")
            CredentialStatus.SUSPENDED -> reject(RejectionReason.SUSPENDED, "credential is suspended")
            CredentialStatus.APPLICATION_SPECIFIC ->
                reject(RejectionReason.STATUS_NOT_VALID, "credential status is not valid")
            CredentialStatus.UNKNOWN ->
                reject(RejectionReason.STATUS_CHECK_FAILED, "credential status could not be determined")
        }
    }

    private companion object {
        /**
         * The issuer envelope: every RFC 7519 registered claim that dates or identifies the
         * credential, plus the SD-JWT VC machinery. Never part of an outcome — see
         * [withoutInternalClaims] for why, and for why `iss` and `vct` are not listed.
         */
        private val ENVELOPE_CLAIMS =
            setOf("cnf", "status", "sub", "aud", "exp", "nbf", "iat", "jti", "_sd_alg")

        /** `dc+sd-jwt` is the current media type; `vc+sd-jwt` is the earlier draft, still in the wild. */
        private val ISSUER_JWT_TYPS = setOf("dc+sd-jwt", "vc+sd-jwt")

        private val KEY_BINDING_TYPS = setOf("kb+jwt")

        /**
         * Tolerance for the ISSUER's clock differing from ours on `exp`/`nbf` — the same
         * minute the status list checker and the trust chain walk already allow. This was
         * the one temporal check in the pipeline with no tolerance at all: the NTP drift
         * the federation code deliberately forgives would have rejected a freshly issued
         * credential here. The key binding freshness check needs none of this — its window
         * is minutes wide and symmetric already.
         */
        private val CLOCK_SKEW: java.time.Duration = java.time.Duration.ofMinutes(1)

        /** See [checkTemporalValidity]: fifty years of 365 days. */
        private val MAX_EXP_AHEAD: Duration = Duration.ofDays(50L * 365)
    }
}
