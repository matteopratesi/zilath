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
package dev.varco.verifier.openid4vp

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.MessageDigest
import java.time.Clock
import java.util.Date

/**
 * Issues verification receipts: the signed artifact a venue keeps INSTEAD of any document
 * (plan docs/03 §5-M0.5). A receipt proves that a verification happened and what its
 * outcome was — never why: it carries the transaction id, the timestamp, the outcome,
 * the claim paths that were REQUESTED and a hash of the request. No claim values, no
 * personal data, no health data.
 */
class VerificationReceipts(
    private val config: RelyingPartyConfiguration,
    private val clock: Clock,
) {
    fun issue(
        txId: TransactionId,
        request: PresentationRequest,
        verified: Boolean,
    ): String {
        val claims =
            JWTClaimsSet
                .Builder()
                .issuer(config.clientId)
                .jwtID(txId.value)
                .issueTime(Date.from(clock.instant()))
                .claim("outcome", if (verified) "verified" else "rejected")
                .claim("entitled", verified)
                .claim("requested_claims", requestedClaimPaths(request.dcqlQuery))
                .claim("request_hash", sha256Base64Url(request.dcqlQuery.toString()))
                .build()
        val header =
            JWSHeader
                .Builder(JWSAlgorithm.ES256)
                .keyID(config.keys.requestSigningKey.keyID)
                .type(JOSEObjectType(RECEIPT_TYP))
                .build()
        val jwt = SignedJWT(header, claims)
        jwt.sign(ECDSASigner(config.keys.requestSigningKey))
        return jwt.serialize()
    }

    companion object {
        const val RECEIPT_TYP = "varco-receipt+jwt"
    }
}

/** The dot-joined claim paths requested by a DCQL query, across all credential queries. */
internal fun requestedClaimPaths(dcqlQuery: JsonObject): List<String> {
    val credentials = dcqlQuery["credentials"] as? JsonArray ?: return emptyList()
    return credentials
        .filterIsInstance<JsonObject>()
        .flatMap { credential -> (credential["claims"] as? JsonArray).orEmpty() }
        .filterIsInstance<JsonObject>()
        .mapNotNull { claim ->
            (claim["path"] as? JsonArray)
                ?.filterIsInstance<JsonPrimitive>()
                ?.joinToString(".") { it.content }
        }
}

private fun sha256Base64Url(value: String): String =
    Base64URL
        .encode(MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8)))
        .toString()
