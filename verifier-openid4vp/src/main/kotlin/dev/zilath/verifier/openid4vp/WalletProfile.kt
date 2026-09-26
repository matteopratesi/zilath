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

import com.nimbusds.jose.jwk.ECKey
import dev.zilath.verifier.core.RejectionReason
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

/**
 * The profile seam: everything that a national or European wallet profile is allowed
 * to change about the OpenID4VP relying-party flow, without touching the flow itself.
 *
 * The baseline is OpenID4VP 1.0 / the EUDI ARF; [ItWalletProfile] is the first national
 * profile (Italy, IT-Wallet v1.4.x) and the library default. Further profiles implement
 * this interface — the transaction machinery, replay protection, TTL and receipts are
 * profile-independent by design.
 */
interface WalletProfile {
    /**
     * Short identifier used in logs and documentation (e.g. `it-wallet-1.4`).
     *
     * It names the specification LINE, not a patch release: the RP flow requirements are
     * identical across 1.4.x, so pinning the patch number here would mean changing an
     * observable value — one that lands in an integrator's logs — on every documentation
     * release of the specification.
     */
    val name: String

    /** The `response_mode` the request object announces and the response endpoint accepts. */
    val responseMode: String

    /**
     * Whether a `vp_token` that is a bare presentation string, instead of the object keyed
     * by credential query id OpenID4VP 1.0 §8.1 defines, is accepted. It is the pre-1.0
     * shape; IT-Wallet says the `vp_token` MUST be a JSON object. False unless a profile
     * needs the legacy form.
     */
    val acceptsBareVpToken: Boolean get() = false

    /**
     * The `client_metadata` object embedded in the request object. [responseEncryptionJwk]
     * is the PUBLIC half of the transaction's own encryption key, the one to publish.
     */
    fun clientMetadataFor(
        config: RelyingPartyConfiguration,
        responseEncryptionJwk: ECKey,
    ): Map<String, Any>

    /**
     * Decodes the wallet's authorization response body into the response JSON
     * (`vp_token`, `state`, ...). Throws a flow rejection on undecodable input.
     * [transactionKey] is the transaction's own encryption key, private half included, or
     * null when the transaction holds none.
     */
    fun decodeWalletResponse(
        body: DirectPostBody,
        config: RelyingPartyConfiguration,
        transactionKey: ECKey?,
    ): JsonObject
}

/**
 * IT-Wallet v1.4.x (docs/spec-version.md): `direct_post.jwt` is MANDATORY — the response
 * is always a JWE encrypted to the RP key advertised in `client_metadata.jwks`.
 */
object ItWalletProfile : WalletProfile {
    override val name: String = "it-wallet-1.4"
    override val responseMode: String = "direct_post.jwt"

    override fun clientMetadataFor(
        config: RelyingPartyConfiguration,
        responseEncryptionJwk: ECKey,
    ): Map<String, Any> =
        baselineClientMetadata(responseEncryptionJwk) +
            mapOf(
                // Legacy JARM member names, kept as harmless extras for older wallets.
                "authorization_encrypted_response_alg" to RESPONSE_ENCRYPTION_ALG,
                "authorization_encrypted_response_enc" to RESPONSE_ENCRYPTION_ENC,
            )

    override fun decodeWalletResponse(
        body: DirectPostBody,
        config: RelyingPartyConfiguration,
        transactionKey: ECKey?,
    ): JsonObject {
        val jwe = body.response ?: flowReject(RejectionReason.MALFORMED, "missing response parameter")
        return decryptWalletResponse(jwe, config, transactionKey)
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

    /**
     * Kept for wallets on the pre-1.0 drafts, which post the presentation itself as the
     * `vp_token` form parameter. Refusing it here would deny holders this profile exists
     * to serve; [ItWalletProfile] refuses it.
     */
    override val acceptsBareVpToken: Boolean = true

    override fun clientMetadataFor(
        config: RelyingPartyConfiguration,
        responseEncryptionJwk: ECKey,
    ): Map<String, Any> = baselineClientMetadata(responseEncryptionJwk)

    override fun decodeWalletResponse(
        body: DirectPostBody,
        config: RelyingPartyConfiguration,
        transactionKey: ECKey?,
    ): JsonObject {
        val vpToken = body.parameters["vp_token"] ?: flowReject(RejectionReason.MALFORMED, "missing vp_token parameter")
        // The form parameter is either the JSON object of OpenID4VP 1.0 or, in the legacy
        // shape, the presentation itself. Anything that does not parse as a JSON structure
        // is the latter: kotlinx reads an unquoted token as a NON-string primitive, which
        // must not stand in for the presentation string.
        val parsedVpToken =
            runCatching { Json.parseToJsonElement(vpToken) }
                .getOrNull()
                ?.takeIf { it is JsonObject || it is JsonArray }
                ?: JsonPrimitive(vpToken)
        return buildJsonObject {
            put("vp_token", parsedVpToken)
            body.parameters["state"]?.let { put("state", JsonPrimitive(it)) }
        }
    }
}

/**
 * A response-encryption key as published: public half, `alg` (so the wallet can pick it)
 * and `use: "enc"` — verifiers are expected to advertise the key USE.
 */
internal fun publicEncryptionJwk(key: ECKey): ECKey =
    ECKey
        .Builder(key.toPublicJWK())
        .algorithm(com.nimbusds.jose.JWEAlgorithm.ECDH_ES)
        .keyUse(com.nimbusds.jose.jwk.KeyUse.ENCRYPTION)
        .build()

/**
 * The SD-JWT issuer and key-binding algorithms this verifier advertises, in the request
 * object's `client_metadata` AND in the federation entity configuration — one constant so the
 * two cannot disagree. They did: the entity configuration said ES256/384/512 while the request
 * object said ES256 alone (third review). `jwsVerifierFor` accepts every EC curve and RSA;
 * what is advertised is the EC family the IT-Wallet profile names.
 */
internal val SUPPORTED_SD_JWT_ALGS = listOf("ES256", "ES384", "ES512")
internal val SUPPORTED_KB_JWT_ALGS = listOf("ES256")

/**
 * [metadata] with the query's credential format among its `vp_formats_supported`, under the
 * algorithms of `dc+sd-jwt`. A query for the pre-1.0 `vc+sd-jwt` came with metadata naming
 * `dc+sd-jwt` alone: the signed request asked for a format it said it did not support, and a
 * wallet that checks one against the other refused it. What a profile names itself is kept.
 */
internal fun withRequestedFormat(
    metadata: Map<String, Any>,
    request: PresentationRequest,
): Map<String, Any> {
    val credential = (request.dcqlQuery["credentials"] as? JsonArray)?.firstOrNull() as? JsonObject
    val format = (credential?.get("format") as? JsonPrimitive)?.content
    val formats = metadata["vp_formats_supported"] as? Map<*, *>
    val template = formats?.get(DC_SD_JWT)
    return when {
        format == null || formats == null || template == null -> metadata
        format in formats -> metadata
        else -> metadata + ("vp_formats_supported" to formats + (format to template))
    }
}

private const val DC_SD_JWT = "dc+sd-jwt"

/**
 * The members every profile shares: the transaction's encryption key — the only key the
 * request publishes — and the supported encodings and formats.
 */
internal fun baselineClientMetadata(responseEncryptionJwk: ECKey): Map<String, Any> =
    mapOf(
        "jwks" to
            mapOf(
                "keys" to
                    listOf(
                        // The wallet selects the response encryption key by its alg.
                        publicEncryptionJwk(responseEncryptionJwk).toJSONObject(),
                    ),
            ),
        "encrypted_response_enc_values_supported" to ACCEPTED_RESPONSE_ENCS,
        "vp_formats_supported" to
            mapOf(
                "dc+sd-jwt" to
                    mapOf(
                        "sd-jwt_alg_values" to SUPPORTED_SD_JWT_ALGS,
                        "kb-jwt_alg_values" to SUPPORTED_KB_JWT_ALGS,
                    ),
            ),
    )
