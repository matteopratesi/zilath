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
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import eu.europa.ec.eudi.sdjwt.SdJwtAndKbJwt
import kotlinx.coroutines.runBlocking
import java.time.Duration

/**
 * Verifies SD-JWT VC presentations (issuer JWT + selective disclosures + key binding JWT)
 * against the checks required by the project plan (docs/03 §5-M0.2):
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
        val issuerKeys = trustedIssuerKeys(issuerJwt, ctx)
        val verified = verifyWithEudiLibrary(compact, issuerKeys)
        val issuerClaims = verified.sdJwt.jwt.jwtClaimsSet
        checkTemporalValidity(issuerClaims, ctx)
        checkKeyBinding(verified.keyBindingJwt.jwtClaimsSet, compact, ctx)
        checkStatus(issuerClaims, issuerKeys, ctx)
        val claims = with(NimbusSdJwtOps) { verified.sdJwt.recreateClaims(null) }
        return VerificationResult.Verified(DisclosedClaims(claims))
    }

    private fun trustedIssuerKeys(
        issuerJwt: SignedJWT,
        ctx: VerificationContext,
    ) = when (val decision = ctx.trustEvaluator.evaluate(trustInputOf(issuerJwt))) {
        is TrustDecision.Trusted ->
            decision.issuerKeys.ifEmpty { reject(RejectionReason.UNTRUSTED_ISSUER, "no trusted issuer keys") }
        is TrustDecision.Untrusted -> reject(RejectionReason.UNTRUSTED_ISSUER, decision.reason)
    }

    private fun verifyWithEudiLibrary(
        compact: String,
        issuerKeys: List<com.nimbusds.jose.jwk.JWK>,
    ): SdJwtAndKbJwt<SignedJWT> =
        runBlocking {
            NimbusSdJwtOps.verify(issuerSignatureVerifier(issuerKeys), holderKeyBindingVerifier(), compact)
        }.getOrElse { failure -> throw rejectionOf(failure) }

    private fun checkTemporalValidity(
        issuerClaims: JWTClaimsSet,
        ctx: VerificationContext,
    ) {
        val now = ctx.clock.instant()
        val expiration = issuerClaims.expirationTime?.toInstant()
        if (expiration != null && !expiration.isAfter(now)) {
            reject(RejectionReason.EXPIRED, "credential expired at $expiration")
        }
        val notBefore = issuerClaims.notBeforeTime?.toInstant()
        if (notBefore != null && notBefore.isAfter(now)) {
            reject(RejectionReason.NOT_YET_VALID, "credential not valid before $notBefore")
        }
    }

    private fun checkKeyBinding(
        kbClaims: JWTClaimsSet,
        compact: String,
        ctx: VerificationContext,
    ) {
        if (kbClaims.audience.orEmpty().none { it in ctx.expectedAudiences }) {
            reject(RejectionReason.AUDIENCE_MISMATCH, "key binding not addressed to this verifier")
        }
        val nonce = runCatching { kbClaims.getStringClaim("nonce") }.getOrNull()
        if (nonce != ctx.expectedNonce) {
            reject(RejectionReason.NONCE_MISMATCH, "key binding nonce does not match the transaction")
        }
        checkKeyBindingFreshness(kbClaims, ctx)
        val sdHash = runCatching { kbClaims.getStringClaim("sd_hash") }.getOrNull()
        if (sdHash != sdHashOf(compact)) {
            reject(RejectionReason.INVALID_KEY_BINDING, "sd_hash does not match the presented credential")
        }
    }

    private fun checkKeyBindingFreshness(
        kbClaims: JWTClaimsSet,
        ctx: VerificationContext,
    ) {
        val issuedAt =
            kbClaims.issueTime?.toInstant()
                ?: reject(RejectionReason.INVALID_KEY_BINDING, "key binding has no iat")
        val distance = Duration.between(issuedAt, ctx.clock.instant()).abs()
        if (distance > ctx.keyBindingMaxAge) {
            reject(RejectionReason.INVALID_KEY_BINDING, "key binding iat outside the accepted window")
        }
    }

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
            CredentialStatus.UNKNOWN ->
                reject(RejectionReason.STATUS_CHECK_FAILED, "credential status could not be determined")
        }
    }
}
