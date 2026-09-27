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
package dev.zilath.verifier.openid4vp

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
 * A receipt proves that a verification happened and what its
 * outcome was — never why: it carries the transaction id, the timestamp, the outcome,
 * the claim paths that were REQUESTED and a hash of the request. No claim values, no
 * personal data, no health data.
 */
class VerificationReceipts(
    private val config: RelyingPartyConfiguration,
    private val clock: Clock,
) {
    /**
     * Issues a signed receipt for [txId] and returns it in compact JWS serialization.
     *
     * [request] contributes only the REQUESTED claim paths and a hash of the DCQL query —
     * what was asked, never what was answered. [outcome] is the whole outcome: whether the
     * presentation was verified (the receipt's `outcome`) and the caller's verdict on the
     * disclosed claims (its `entitled`). A receipt for a rejection is as legitimate as one
     * for a success, and neither says why.
     *
     * Issue it once the application has applied its policy to the verified claims, not
     * before: `entitled` states that decision. It used to be a copy of `outcome`, so a card
     * that verified but granted nothing was archived as an entitlement.
     *
     * Safe to keep and to hand to an auditor. That is the point: it is what a venue
     * archives instead of a copy of someone's medical paperwork.
     */
    fun issue(
        txId: TransactionId,
        request: PresentationRequest,
        outcome: ReceiptOutcome,
    ): String {
        val claims =
            JWTClaimsSet
                .Builder()
                .issuer(config.clientId)
                .jwtID(txId.value)
                .issueTime(Date.from(clock.instant()))
                .claim("outcome", if (outcome.verified) "verified" else "rejected")
                .claim("entitled", outcome.entitled)
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
        const val RECEIPT_TYP = "zilath-receipt+jwt"
    }
}

/**
 * What a receipt records: whether the presentation was verified and, for a verified one, the
 * CALLER's verdict on whether the disclosed claims entitle the holder to what was asked.
 * Verifying is the library's job; deciding entitlement from a claim's value is the
 * application's policy — a disability card can verify and still grant no companion ticket —
 * so the application states it here.
 */
enum class ReceiptOutcome(
    internal val verified: Boolean,
    internal val entitled: Boolean,
) {
    /** Verified, and the application's policy grants the entitlement. */
    VERIFIED_ENTITLED(verified = true, entitled = true),

    /** Verified, but under the application's policy the disclosed claims grant nothing. */
    VERIFIED_NOT_ENTITLED(verified = true, entitled = false),

    /** Not verified: a rejected presentation or a wallet error. Never entitled. */
    REJECTED(verified = false, entitled = false),
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
