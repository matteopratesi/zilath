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
private fun checkTypIfPresent(
    header: JWSHeader,
    accepted: Set<String>,
    reason: RejectionReason,
) {
    val typ = header.type?.toString() ?: return
    if (typ !in accepted) reject(reason, "unexpected typ header")
}

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
        checkTypIfPresent(issuerJwt.header, ISSUER_JWT_TYPS, RejectionReason.UNSUPPORTED_FORMAT)
        val issuerKeys = trustedIssuerKeys(issuerJwt, ctx)
        val verified = verifyWithEudiLibrary(compact, issuerKeys)
        val issuerClaims = verified.sdJwt.jwt.jwtClaimsSet
        checkCredentialType(issuerClaims, ctx)
        checkTemporalValidity(issuerClaims, ctx)
        checkTypIfPresent(verified.keyBindingJwt.header, KEY_BINDING_TYPS, RejectionReason.INVALID_KEY_BINDING)
        checkKeyBinding(verified.keyBindingJwt.jwtClaimsSet, compact, ctx)
        checkStatus(issuerClaims, issuerKeys, ctx)
        val claims = with(NimbusSdJwtOps) { verified.sdJwt.recreateClaims(null) }
        return VerificationResult.Verified(DisclosedClaims(withoutInternalClaims(claims)))
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
     * `detail` is retained on the transaction and reaches the application log, so it carries
     * no value taken from the credential — not even a timestamp. The reason code says what
     * failed; the exact instant is the holder's, not the log's.
     */
    private fun checkTemporalValidity(
        issuerClaims: JWTClaimsSet,
        ctx: VerificationContext,
    ) {
        val now = ctx.clock.instant()
        val expiration = issuerClaims.expirationTime?.toInstant()
        if (expiration != null && !expiration.isAfter(now)) {
            reject(RejectionReason.EXPIRED, "credential is expired")
        }
        val notBefore = issuerClaims.notBeforeTime?.toInstant()
        if (notBefore != null && notBefore.isAfter(now)) {
            reject(RejectionReason.NOT_YET_VALID, "credential is not yet valid")
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

    /**
     * Strips the claims that exist for verification and have no business reaching the
     * application.
     *
     * `recreateClaims` returns the whole issuer envelope, not only what the holder chose to
     * disclose: `cnf` carries the holder's public key and `status` carries the index of this
     * credential in its issuer's revocation list. Both are STABLE PER CREDENTIAL, so handing
     * them over would let an integrator — or anything downstream of them — link two
     * verifications of the same person across venues and across months. The library has
     * finished with them by the time it returns; nobody else needs them.
     */
    private fun withoutInternalClaims(claims: JsonObject): JsonObject =
        JsonObject(claims.filterKeys { it !in INTERNAL_CLAIMS })

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

    private companion object {
        /** Verification machinery, and stable identifiers: never part of an outcome. */
        private val INTERNAL_CLAIMS = setOf("cnf", "status")

        /** `dc+sd-jwt` is the current media type; `vc+sd-jwt` is the earlier draft, still in the wild. */
        private val ISSUER_JWT_TYPS = setOf("dc+sd-jwt", "vc+sd-jwt")

        private val KEY_BINDING_TYPS = setOf("kb+jwt")
    }
}
