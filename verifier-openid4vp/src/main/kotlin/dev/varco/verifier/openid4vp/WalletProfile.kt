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

import dev.varco.verifier.core.RejectionReason
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

/**
 * The profile seam: everything that a national or European wallet profile is allowed
 * to change about the OpenID4VP relying-party flow, without touching the flow itself.
 *
 * The baseline is OpenID4VP 1.0 / the EUDI ARF; [ItWalletProfile] is the first national
 * profile (Italy, IT-Wallet v1.4.5) and the library default. Further profiles implement
 * this interface — the transaction machinery, replay protection, TTL and receipts are
 * profile-independent by design.
 */
interface WalletProfile {
    /** Short identifier used in logs and documentation (e.g. `it-wallet-1.4.5`). */
    val name: String

    /** The `response_mode` the request object announces and the response endpoint accepts. */
    val responseMode: String

    /** The `client_metadata` object embedded in the request object. */
    fun clientMetadataFor(config: RelyingPartyConfiguration): Map<String, Any>

    /**
     * Decodes the wallet's authorization response body into the response JSON
     * (`vp_token`, `state`, ...). Throws a flow rejection on undecodable input.
     */
    fun decodeWalletResponse(
        body: DirectPostBody,
        config: RelyingPartyConfiguration,
    ): JsonObject
}

/**
 * IT-Wallet v1.4.5 (docs/spec-version.md): `direct_post.jwt` is MANDATORY — the response
 * is always a JWE encrypted to the RP key advertised in `client_metadata.jwks`.
 */
object ItWalletProfile : WalletProfile {
    override val name: String = "it-wallet-1.4.5"
    override val responseMode: String = "direct_post.jwt"

    override fun clientMetadataFor(config: RelyingPartyConfiguration): Map<String, Any> =
        baselineClientMetadata(config) +
            mapOf(
                // Legacy JARM member names, kept as harmless extras for older wallets.
                "authorization_encrypted_response_alg" to RESPONSE_ENCRYPTION_ALG,
                "authorization_encrypted_response_enc" to RESPONSE_ENCRYPTION_ENC,
            )

    override fun decodeWalletResponse(
        body: DirectPostBody,
        config: RelyingPartyConfiguration,
    ): JsonObject {
        val jwe = body.response ?: flowReject(RejectionReason.MALFORMED, "missing response parameter")
        return decryptWalletResponse(jwe, config)
    }
}

/**
 * Plain OpenID4VP 1.0 / ARF baseline: unencrypted `direct_post`, with `vp_token` and
 * `state` as form parameters. Useful against non-Italian EUDI reference wallets and as
 * the template for further national profiles.
 */
object ArfBaselineProfile : WalletProfile {
    override val name: String = "arf-baseline"
    override val responseMode: String = "direct_post"

    override fun clientMetadataFor(config: RelyingPartyConfiguration): Map<String, Any> = baselineClientMetadata(config)

    override fun decodeWalletResponse(
        body: DirectPostBody,
        config: RelyingPartyConfiguration,
    ): JsonObject {
        val vpToken = body.parameters["vp_token"] ?: flowReject(RejectionReason.MALFORMED, "missing vp_token parameter")
        val parsedVpToken =
            runCatching { Json.parseToJsonElement(vpToken) }.getOrElse { JsonPrimitive(vpToken) }
        return buildJsonObject {
            put("vp_token", parsedVpToken)
            body.parameters["state"]?.let { put("state", JsonPrimitive(it)) }
        }
    }
}

/** The members every profile shares: RP encryption key, supported encodings and formats. */
internal fun baselineClientMetadata(config: RelyingPartyConfiguration): Map<String, Any> =
    mapOf(
        "jwks" to
            mapOf(
                "keys" to
                    listOf(
                        // The wallet selects the response encryption key by its alg.
                        com.nimbusds.jose.jwk
                            .ECKey
                            .Builder(
                                config.keys.responseEncryptionKey
                                    .toPublicJWK()
                                    .toECKey(),
                            ).algorithm(com.nimbusds.jose.JWEAlgorithm.ECDH_ES)
                            .build()
                            .toJSONObject(),
                    ),
            ),
        "encrypted_response_enc_values_supported" to listOf(RESPONSE_ENCRYPTION_ENC, "A128GCM"),
        "vp_formats_supported" to
            mapOf(
                "dc+sd-jwt" to
                    mapOf(
                        "sd-jwt_alg_values" to listOf("ES256"),
                        "kb-jwt_alg_values" to listOf("ES256"),
                    ),
            ),
    )
