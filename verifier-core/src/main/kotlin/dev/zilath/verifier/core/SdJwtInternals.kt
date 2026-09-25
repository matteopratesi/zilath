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

import com.nimbusds.jose.Header
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.JwtSignatureVerifier
import eu.europa.ec.eudi.sdjwt.KeyBindingVerifier
import eu.europa.ec.eudi.sdjwt.SdJwtVerificationException
import eu.europa.ec.eudi.sdjwt.VerificationError
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

private const val TILDE = '~'

/** Internal short-circuit carrying the rejection out of the verification pipeline. */
internal class SdJwtRejection(
    val reason: RejectionReason,
    val detail: String?,
) : RuntimeException(detail ?: reason.name)

internal fun reject(
    reason: RejectionReason,
    detail: String? = null,
): Nothing = throw SdJwtRejection(reason, detail)

/**
 * Parses the issuer-signed JWT part of a compact SD-JWT without verifying it.
 *
 * Nimbus refuses a JOSE header longer than [Header.MAX_HEADER_STRING_LENGTH] decoded
 * characters, and so does the EUDI library, which parses the same JWT with Nimbus again. The
 * limit is not configurable, and a legitimate header can exceed it: IT-Wallet 1.4.6 lets an
 * issuer embed its federation `trust_chain` in the header, and the production disability
 * card issuer's entity configuration alone is 39,668 characters. The signature covers the
 * header, so nothing can be dropped before parsing either. Such a credential cannot be
 * verified with this library today; what the fourth internal review found wrong is that
 * it was reported as unparseable, indistinguishable from garbage. It now has its own phrase.
 */
internal fun parseIssuerJwt(compact: String): SignedJWT {
    val issuerJwt = compact.substringBefore(TILDE)
    val header =
        runCatching { Base64URL(issuerJwt.substringBefore('.')).decodeToString() }
            .getOrElse { reject(RejectionReason.MALFORMED, "issuer JWT does not parse") }
    if (header.length > Header.MAX_HEADER_STRING_LENGTH) {
        reject(RejectionReason.MALFORMED, "issuer JWT header exceeds the parser limit")
    }
    return runCatching { SignedJWT.parse(issuerJwt) }
        .getOrElse { reject(RejectionReason.MALFORMED, "issuer JWT does not parse") }
}

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

/** One key-acceptance rule for issuer, holder and status list keys alike: see [acceptableJwsVerifierFor]. */
@OptIn(InternalZilathApi::class)
internal fun jwsVerifierFor(key: JWK): JWSVerifier? = acceptableJwsVerifierFor(key)

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

/**
 * Extracts the OAuth Status List reference, if the credential carries one.
 *
 * Only the Token Status List mechanism (`status.status_list`) is evaluated. A `status`
 * object that carries other members and no `status_list` — IT-Wallet's earlier
 * `status_assertion` and `status_attestation`, which the production disability card issuer
 * still advertises — is well formed (draft-ietf-oauth-status-list §6.1 lets other
 * specifications define members), but the library cannot evaluate it, so the credential is
 * rejected. Its own phrase says so, where the fourth internal review found the same words
 * as for a broken reference: an operator must be able to tell "unsupported" from "wrong".
 */
@OptIn(InternalZilathApi::class)
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
        when (val member = status["status_list"]) {
            is Map<*, *> -> member
            null ->
                if (status.isEmpty()) {
                    reject(RejectionReason.STATUS_CHECK_FAILED, "status claim without a status_list reference")
                } else {
                    reject(RejectionReason.STATUS_CHECK_FAILED, "status mechanism not supported")
                }
            else -> reject(RejectionReason.STATUS_CHECK_FAILED, "malformed status_list reference")
        }
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
    // The fetcher is handed this URI, and the issuer chose it: SECURITY.md B1 promises the
    // same shape rule as for federation URLs, which the fourth internal review found was
    // never applied here — file:, http: to a metadata address, userinfo and bare IPs all
    // reached the fetcher.
    if (usableHttpsUriOrNull(uri) == null) {
        reject(RejectionReason.STATUS_CHECK_FAILED, "status_list uri is not a usable https url")
    }
    return StatusReference(uri, index)
}
