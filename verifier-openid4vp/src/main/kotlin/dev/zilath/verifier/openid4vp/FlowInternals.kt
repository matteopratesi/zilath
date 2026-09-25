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
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.RejectionReason
import kotlinx.serialization.json.JsonObject
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.time.Instant
import java.util.Date

/*
 * Profile-independent request machinery; everything a profile may change lives
 * behind [WalletProfile] (response mode, client_metadata, response decoding).
 */
internal const val REQUEST_OBJECT_TYP = "oauth-authz-req+jwt"

/** OpenID4VP §5.8: `aud` of a request object addressed to a wallet (static discovery). */
internal const val WALLET_AUDIENCE = "https://self-issued.me/v2"

private val secureRandom = SecureRandom()

/**
 * The forms of THIS verifier's identifier a key binding may be addressed to: the
 * `client_id` as sent, plus — when it carries a Client Identifier Prefix — the same
 * identifier without it.
 *
 * OpenID4VP 1.0 (App. B.3.6) says the audience is the Client Identifier, prefix included,
 * and its example shows exactly that; the IT-Wallet rules say it must match the "Relying
 * Party unique entity identifier", which reads as the stripped form. Wallets exist on
 * both readings, so both are accepted — never a third party's identifier, only ours
 * written two ways. Tracked upstream: pagopa/wallet-conformance-test#221.
 */
internal fun acceptedAudiencesFor(clientId: String): Set<String> {
    val prefix = CLIENT_ID_PREFIXES.firstOrNull { clientId.startsWith(it) }
    val stripped = prefix?.let { clientId.removePrefix(it) }?.takeIf { it.isNotBlank() }
    return setOfNotNull(clientId, stripped)
}

private val CLIENT_ID_PREFIXES = listOf(OPENID_FEDERATION_PREFIX, X509_HASH_PREFIX)

/**
 * The `x509_hash` client identifier of a certificate: the base64url-encoded SHA-256 hash of
 * its DER encoding (OpenID4VP 1.0 §5.9.3). [certificate] is an `x5c` element, which is
 * standard base64 of the DER.
 */
internal fun x509HashOf(certificate: Base64): String =
    Base64URL
        .encode(
            java.security.MessageDigest
                .getInstance("SHA-256")
                .digest(certificate.decode()),
        ).toString()

/** Internal short-circuit carrying a rejection out of the response pipeline. */
internal class FlowRejection(
    val reason: RejectionReason,
    val detail: String?,
) : RuntimeException(detail ?: reason.name)

internal fun flowReject(
    reason: RejectionReason,
    detail: String? = null,
): Nothing = throw FlowRejection(reason, detail)

/**
 * Compares two secrets in time that depends on their length only, never on where they
 * first differ: a code or token presented by an unauthenticated caller is checked with it.
 */
internal fun secretsEqual(
    expected: String,
    presented: String,
): Boolean = java.security.MessageDigest.isEqual(expected.toByteArray(), presented.toByteArray())

/** What a transaction keeps of its [PollToken]: base64url SHA-256. */
internal fun pollTokenHashOf(token: String): String =
    Base64URL
        .encode(
            java.security.MessageDigest
                .getInstance("SHA-256")
                .digest(token.toByteArray()),
        ).toString()

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
            .claim("response_mode", config.profile.responseMode)
            .claim("response_uri", "${config.endpoints.responseUriBase}/${transaction.id.value}")
            .claim("nonce", transaction.nonce)
            .claim("state", transaction.id.value)
            .claim("dcql_query", jsonToMap(transaction.request.dcqlQuery))
            .claim(
                "client_metadata",
                // Public half only: a profile publishes what it is given.
                config.profile.clientMetadataFor(config, responseEncryptionKeyOf(config, transaction).toPublicJWK()),
            ).issueTime(Date.from(now))
            // The JAR must not advertise a validity window outliving the transaction itself.
            .expirationTime(Date.from(transaction.expiresAt))
            .build()
    val headerBuilder =
        JWSHeader
            .Builder(JWSAlgorithm.ES256)
            .keyID(config.keys.requestSigningKey.keyID)
            .type(JOSEObjectType(REQUEST_OBJECT_TYP))
    // x509_hash client id scheme: the JAR carries the RP certificate chain (spec v1.4.x).
    config.keys.requestSigningKey.x509CertChain
        ?.takeIf { it.isNotEmpty() }
        ?.let(headerBuilder::x509CertChain)
    // openid_federation client id scheme: the RP trust chain travels in the JAR header so
    // the wallet can validate the RP offline (spec v1.4.6, remote flow).
    config.federation
        ?.let { trustChainHeaderFor(it, now) }
        ?.let { headerBuilder.customParam("trust_chain", it) }
    val header = headerBuilder.build()
    val jwt = SignedJWT(header, claims)
    jwt.sign(ECDSASigner(config.keys.requestSigningKey))
    return jwt.serialize()
}

/**
 * The key a request object publishes for [transaction]: its own, or the static fallback for
 * a transaction a store handed back without one. Neither is a store that lost the key.
 */
private fun responseEncryptionKeyOf(
    config: RelyingPartyConfiguration,
    transaction: Transaction,
): ECKey =
    checkNotNull(transaction.responseEncryptionKey ?: config.keys.responseEncryptionKey) {
        "the transaction holds no response encryption key and no static one is configured"
    }

private fun jsonToMap(json: JsonObject): Map<String, Any?> =
    com.nimbusds.jose.util.JSONObjectUtils
        .parse(json.toString())
