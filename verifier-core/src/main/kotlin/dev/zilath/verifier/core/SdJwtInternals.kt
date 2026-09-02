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

import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.JwtSignatureVerifier
import eu.europa.ec.eudi.sdjwt.KeyBindingVerifier
import eu.europa.ec.eudi.sdjwt.SdJwtVerificationException
import eu.europa.ec.eudi.sdjwt.VerificationError
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.security.MessageDigest

private const val TILDE = '~'
private const val SHA_256 = "SHA-256"

/** Internal short-circuit carrying the rejection out of the verification pipeline. */
internal class SdJwtRejection(
    val reason: RejectionReason,
    val detail: String?,
) : RuntimeException(detail ?: reason.name)

internal fun reject(
    reason: RejectionReason,
    detail: String? = null,
): Nothing = throw SdJwtRejection(reason, detail)

/** Parses the issuer-signed JWT part of a compact SD-JWT without verifying it. */
internal fun parseIssuerJwt(compact: String): SignedJWT =
    runCatching { SignedJWT.parse(compact.substringBefore(TILDE)) }
        .getOrElse { reject(RejectionReason.MALFORMED, "issuer JWT does not parse") }

internal fun trustInputOf(issuerJwt: SignedJWT): IssuerTrustInput =
    IssuerTrustInput(
        issuer = runCatching { issuerJwt.jwtClaimsSet.issuer }.getOrNull(),
        keyId = issuerJwt.header.keyID,
        certificateChain =
            issuerJwt.header.x509CertChain
                .orEmpty()
                .map { it.toString() },
        trustChain =
            (issuerJwt.header.getCustomParam("trust_chain") as? List<*>)
                .orEmpty()
                .filterIsInstance<String>(),
    )

/** Accepts the issuer JWT only if its signature verifies against one of the trusted keys. */
internal fun issuerSignatureVerifier(trustedKeys: List<JWK>): JwtSignatureVerifier<SignedJWT> =
    JwtSignatureVerifier { unverifiedJwt ->
        runCatching {
            val jwt = SignedJWT.parse(unverifiedJwt)
            // Each key attempt is isolated: a verifier throwing on an algorithm mismatch
            // (e.g. an EC key against an RS256 JWT) must not prevent trying the next key.
            val verifies =
                trustedKeys.any { key ->
                    runCatching { jwsVerifierFor(key)?.let(jwt::verify) == true }.getOrDefault(false)
                }
            if (verifies) jwt else null
        }.getOrNull()
    }

/** Requires a key binding JWT signed with the holder key advertised in the `cnf.jwk` claim. */
internal fun holderKeyBindingVerifier(): KeyBindingVerifier.MustBePresentAndValid<SignedJWT> =
    KeyBindingVerifier.MustBePresentAndValid { issuerClaims: JsonObject ->
        holderKeyOf(issuerClaims)?.let { holderKey ->
            JwtSignatureVerifier { unverifiedJwt ->
                runCatching {
                    val jwt = SignedJWT.parse(unverifiedJwt)
                    val verifier = jwsVerifierFor(holderKey)
                    if (verifier != null && jwt.verify(verifier)) jwt else null
                }.getOrNull()
            }
        }
    }

private fun holderKeyOf(issuerClaims: JsonObject): JWK? {
    val jwkJson = issuerClaims["cnf"]?.jsonObject?.get("jwk") ?: return null
    return runCatching { JWK.parse(jwkJson.toString()) }.getOrNull()
}

internal fun jwsVerifierFor(key: JWK): JWSVerifier? =
    when (key.keyType) {
        KeyType.EC -> ECDSAVerifier(key.toECKey())
        KeyType.RSA -> RSASSAVerifier(key.toRSAKey())
        else -> null
    }

/**
 * Maps failures raised by the EUDI SD-JWT library onto stable [RejectionReason]s.
 *
 * The library's message is deliberately NOT carried as `detail`. Its `InvalidDisclosures`,
 * `NonUniqueDisclosures` and `MissingDigests` errors are data classes holding the offending
 * disclosures — claim name and value, base64url-encoded — with a `toString` that prints them.
 * Today the exception message is null and nothing leaks; a library version that fills it in
 * would send someone's claim values to the verifier's log on the failure path. The guarantee
 * that `detail` never carries a claim value has to hold by construction, not by a dependency's
 * current habit, so the detail is a fixed phrase per reason.
 */
internal fun rejectionOf(failure: Throwable): SdJwtRejection =
    when ((failure as? SdJwtVerificationException)?.reason) {
        is VerificationError.InvalidJwt ->
            SdJwtRejection(RejectionReason.INVALID_ISSUER_SIGNATURE, "issuer signature does not verify")
        is VerificationError.KeyBindingFailed ->
            SdJwtRejection(RejectionReason.INVALID_KEY_BINDING, "key binding does not verify")
        is VerificationError.InvalidDisclosures,
        is VerificationError.UnsupportedHashingAlgorithm,
        is VerificationError.NonUniqueDisclosures,
        is VerificationError.NonUniqueDisclosureDigests,
        is VerificationError.MissingDigests,
        -> SdJwtRejection(RejectionReason.DISCLOSURE_TAMPERED, "disclosures do not match the credential")
        else -> SdJwtRejection(RejectionReason.MALFORMED, "presentation does not parse")
    }

/** Recomputes the `sd_hash` the key binding must commit to: SHA-256 over `issuer-jwt~d1~...~`. */
internal fun sdHashOf(compact: String): String {
    val presentedPart = compact.substringBeforeLast(TILDE) + TILDE
    val digest = MessageDigest.getInstance(SHA_256).digest(presentedPart.toByteArray(Charsets.US_ASCII))
    return Base64URL.encode(digest).toString()
}

/** Extracts the OAuth Status List reference, if the credential carries one. */
internal fun statusReferenceOf(issuerClaims: JWTClaimsSet): StatusReference? {
    // Absent is fine: not every credential is revocable. Present but not an object is NOT
    // fine — swallowing that would skip the revocation check entirely, while the sibling
    // case (an object with a malformed status_list, below) fails closed. A credential that
    // says something about its status and says it wrongly is not a credential to trust.
    if (!issuerClaims.claims.containsKey("status")) return null
    val status =
        runCatching { issuerClaims.getJSONObjectClaim("status") }.getOrNull()
            ?: reject(RejectionReason.STATUS_CHECK_FAILED, "status claim is not an object")
    val statusList =
        status["status_list"] as? Map<*, *>
            ?: reject(RejectionReason.STATUS_CHECK_FAILED, "status claim without a status_list reference")
    val uri = statusList["uri"] as? String
    // Two ways a Number can quietly become the wrong entry, and both read somebody else's
    // status bit: toInt() keeps the low 32 bits of anything larger, and toLong() truncates
    // 3.5 to 3. An index that is not a whole number in range is malformed, whatever the
    // issuer meant by it — it is not ours to round.
    val index =
        (statusList["idx"] as? Number)
            ?.takeIf { it.toDouble() == kotlin.math.floor(it.toDouble()) }
            ?.toLong()
            ?.takeIf { it in 0..Int.MAX_VALUE.toLong() }
            ?.toInt()
    if (uri == null || index == null) {
        reject(RejectionReason.STATUS_CHECK_FAILED, "malformed status_list reference")
    }
    return StatusReference(uri, index)
}
