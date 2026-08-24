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
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import dev.varco.verifier.core.RejectionReason
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.time.Instant
import java.util.Date

/**
 * IT-Wallet v1.4.5 request object profile (docs/spec-version.md): JAR typed
 * `oauth-authz-req+jwt`, `response_mode=direct_post.jwt`, `dcql_query`, and the
 * RP encryption key advertised in `client_metadata.jwks`.
 */
internal const val REQUEST_OBJECT_TYP = "oauth-authz-req+jwt"
internal const val RESPONSE_MODE = "direct_post.jwt"
internal const val RESPONSE_ENCRYPTION_ALG = "ECDH-ES"
internal const val RESPONSE_ENCRYPTION_ENC = "A256GCM"

/** OpenID4VP §5.8: `aud` of a request object addressed to a wallet (static discovery). */
internal const val WALLET_AUDIENCE = "https://self-issued.me/v2"

private val secureRandom = SecureRandom()

/** Internal short-circuit carrying a rejection out of the response pipeline. */
internal class FlowRejection(
    val reason: RejectionReason,
    val detail: String?,
) : RuntimeException(detail ?: reason.name)

internal fun flowReject(
    reason: RejectionReason,
    detail: String? = null,
): Nothing = throw FlowRejection(reason, detail)

internal fun randomToken(bytes: Int): String {
    val buffer = ByteArray(bytes)
    secureRandom.nextBytes(buffer)
    return Base64URL.encode(buffer).toString()
}

internal fun qrPayloadOf(
    config: RelyingPartyConfiguration,
    requestUri: String,
): String {
    val clientId = URLEncoder.encode(config.clientId, StandardCharsets.UTF_8)
    val encodedRequestUri = URLEncoder.encode(requestUri, StandardCharsets.UTF_8)
    return "${config.walletAuthorizationScheme}authorize?client_id=$clientId&request_uri=$encodedRequestUri"
}

/** Builds and signs the request object (JAR) for one transaction. */
internal fun buildRequestJwt(
    config: RelyingPartyConfiguration,
    transaction: Transaction,
    now: Instant,
): String {
    val claims =
        JWTClaimsSet
            .Builder()
            .issuer(config.clientId)
            .audience(WALLET_AUDIENCE)
            .claim("client_id", config.clientId)
            .claim("response_type", "vp_token")
            .claim("response_mode", RESPONSE_MODE)
            .claim("response_uri", "${config.endpoints.responseUriBase}/${transaction.id.value}")
            .claim("nonce", transaction.nonce)
            .claim("state", transaction.id.value)
            .claim("dcql_query", jsonToMap(transaction.request.dcqlQuery))
            .claim("client_metadata", clientMetadataOf(config))
            .issueTime(Date.from(now))
            // The JAR must not advertise a validity window outliving the transaction itself.
            .expirationTime(Date.from(transaction.createdAt.plus(config.transactionTimeToLive)))
            .build()
    val headerBuilder =
        JWSHeader
            .Builder(JWSAlgorithm.ES256)
            .keyID(config.keys.requestSigningKey.keyID)
            .type(JOSEObjectType(REQUEST_OBJECT_TYP))
    // x509_hash client id scheme: the JAR carries the RP certificate chain (spec v1.4.5).
    config.keys.requestSigningKey.x509CertChain
        ?.takeIf { it.isNotEmpty() }
        ?.let(headerBuilder::x509CertChain)
    val header = headerBuilder.build()
    val jwt = SignedJWT(header, claims)
    jwt.sign(ECDSASigner(config.keys.requestSigningKey))
    return jwt.serialize()
}

private fun clientMetadataOf(config: RelyingPartyConfiguration): Map<String, Any> =
    mapOf(
        "jwks" to
            mapOf(
                "keys" to
                    listOf(
                        config.keys.responseEncryptionKey
                            .toPublicJWK()
                            .toJSONObject(),
                    ),
            ),
        // IT-Wallet v1.4.5 / OpenID4VP 1.0 member names.
        "encrypted_response_enc_values_supported" to listOf(RESPONSE_ENCRYPTION_ENC, "A128GCM"),
        "vp_formats_supported" to
            mapOf(
                "dc+sd-jwt" to
                    mapOf(
                        "sd-jwt_alg_values" to listOf("ES256"),
                        "kb-jwt_alg_values" to listOf("ES256"),
                    ),
            ),
        // Legacy JARM member names, kept as harmless extras for older wallets.
        "authorization_encrypted_response_alg" to RESPONSE_ENCRYPTION_ALG,
        "authorization_encrypted_response_enc" to RESPONSE_ENCRYPTION_ENC,
    )

private fun jsonToMap(json: JsonObject): Map<String, Any?> =
    com.nimbusds.jose.util.JSONObjectUtils
        .parse(json.toString())

/** Decrypts the `direct_post.jwt` response JWE with the RP encryption key. */
internal fun decryptWalletResponse(
    jwe: String,
    config: RelyingPartyConfiguration,
): JsonObject =
    runCatching {
        val jweObject = JWEObject.parse(jwe)
        jweObject.decrypt(ECDHDecrypter(config.keys.responseEncryptionKey))
        Json.parseToJsonElement(jweObject.payload.toString()) as JsonObject
    }.getOrElse { flowReject(RejectionReason.MALFORMED, "wallet response cannot be decrypted") }

/** Extracts the compact SD-JWT presentation for the requested credential from `vp_token`. */
internal fun extractPresentation(
    payload: JsonObject,
    credentialQueryId: String,
): String {
    val entry =
        when (val vpToken = payload["vp_token"]) {
            is JsonPrimitive -> vpToken
            is JsonObject -> vpToken[credentialQueryId]
            else -> null
        }
    val presentation =
        when (entry) {
            is JsonPrimitive -> entry.content
            is JsonArray -> (entry.firstOrNull() as? JsonPrimitive)?.content
            else -> null
        }
    return presentation ?: flowReject(RejectionReason.MALFORMED, "vp_token has no presentation for the query")
}

/** The `state` echoed by the wallet must match the transaction. */
internal fun checkState(
    payload: JsonObject,
    transaction: Transaction,
) {
    val state = (payload["state"] as? JsonPrimitive)?.jsonPrimitive?.content
    if (state != transaction.id.value) {
        flowReject(RejectionReason.MALFORMED, "response state does not match the transaction")
    }
}
