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
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.time.Clock
import java.time.Duration
import java.util.Date

/** The `openid_federation` client id prefix (IT-Wallet v1.4.6 §remote flow). */
const val OPENID_FEDERATION_PREFIX = "openid_federation:"

/** The `x509_hash` client id prefix (IT-Wallet v1.4.6 §remote flow). */
const val X509_HASH_PREFIX = "x509_hash:"

/**
 * Federation-side identity of the RP: what is needed to publish the entity
 * configuration at `/.well-known/openid-federation` and to onboard into a federation.
 *
 * The [federationKey] signs entity statements and is DISTINCT from the protocol keys in
 * [RpKeys]: federation trust and request signing must be independently rotatable.
 */
@Suppress("LongParameterList") // configuration surface: every axis is independent
data class RpFederationConfig(
    /** The RP's federation entity identifier: an HTTPS URL, the `sub` of its statements. */
    val entityId: String,
    /** EC P-256 key (with kid) signing the RP's own entity configuration. */
    val federationKey: ECKey,
    /** Entity ids of the superiors this RP is (or will be) registered under. */
    val authorityHints: List<String>,
    /** Shown to the user by the wallet and published as `organization_name`. */
    val organizationName: String,
    val contacts: List<String> = emptyList(),
    /**
     * The RP's trust chain (its own entity configuration first, up to the anchor
     * statement), obtained from the federation on onboarding. When present it travels in
     * the JAR `trust_chain` header so wallets can validate the RP offline.
     */
    val trustChain: List<String> = emptyList(),
    val statementValidity: Duration = DEFAULT_STATEMENT_VALIDITY,
) {
    init {
        // The spec mandates HTTPS entity ids with a host; plain http is tolerated for the
        // EXACT localhost hosts only (parsed, not prefix-matched: "http://localhost.evil"
        // must not pass), so the demo and local development need no TLS terminator.
        val uri = runCatching { java.net.URI(entityId) }.getOrNull()
        val host = uri?.host
        val allowed =
            !host.isNullOrBlank() &&
                // OpenID Federation entity identifiers carry no query and no fragment.
                uri.query == null &&
                uri.fragment == null &&
                (uri.scheme == "https" || (uri.scheme == "http" && host in LOCALHOST_HOSTS))
        require(allowed) { "the federation entity id must be an HTTPS URL with a host, no query, no fragment" }
        require(statementValidity > Duration.ZERO) { "statementValidity must be positive (exp must follow iat)" }
        require(federationKey.isPrivate) { "federationKey must contain private key material" }
        require(federationKey.curve == Curve.P_256) { "federationKey must be a P-256 key (IT-Wallet profile)" }
        require(!federationKey.keyID.isNullOrBlank()) { "federationKey must carry a kid" }
        require(authorityHints.isNotEmpty()) { "authorityHints must name at least one superior" }
        authorityHints.forEach { hint ->
            val hintUri = runCatching { java.net.URI(hint) }.getOrNull()
            require(
                hintUri?.scheme == "https" &&
                    !hintUri.host.isNullOrBlank() &&
                    hintUri.query == null &&
                    hintUri.fragment == null,
            ) { "authority hint is not a valid entity id: $hint" }
        }
    }

    /** Nimbus keys serialize their private parameters: never let them reach a log. */
    override fun toString(): String = "RpFederationConfig(federationKey=kid:${federationKey.keyID})"

    companion object {
        val DEFAULT_STATEMENT_VALIDITY: Duration = Duration.ofDays(1)

        private val LOCALHOST_HOSTS = setOf("localhost", "127.0.0.1")
    }
}

/**
 * Builds the RP's signed Entity Configuration (IT-Wallet v1.4.6 §10.3.4): the JWS served
 * at `/.well-known/openid-federation`. Carries the `federation_entity` and
 * `openid_credential_verifier` metadata types; the protocol `jwks` publishes ONLY the
 * public halves of the request-signing and response-encryption keys.
 */
object RpEntityConfiguration {
    /**
     * Returns the entity configuration as a signed JWS, ready to be served verbatim at
     * `/.well-known/openid-federation` with content type `application/entity-statement+jwt`.
     *
     * Self-issued and short-lived: `iss` equals `sub` equals the entity id, and validity
     * comes from [RpFederationConfig.statementValidity], so callers should rebuild it
     * rather than cache it indefinitely. Throws [IllegalArgumentException] if `client_id`
     * and the federation entity id disagree under the `openid_federation` scheme — a
     * mismatch a wallet would reject on every presentation (WP_086).
     */
    fun build(
        config: RelyingPartyConfiguration,
        federation: RpFederationConfig,
        clock: Clock,
    ): String {
        val entityId = federation.entityId
        // With the openid_federation scheme the wallet checks client_id against our `sub`:
        // a mismatch here would fail every presentation (spec v1.4.6, WP_086).
        if (config.clientId.startsWith(OPENID_FEDERATION_PREFIX)) {
            require(config.clientId.removePrefix(OPENID_FEDERATION_PREFIX) == entityId) {
                "client_id and federation entityId must agree under the openid_federation scheme"
            }
        }
        val now = clock.instant()
        val claims =
            JWTClaimsSet
                .Builder()
                .issuer(entityId)
                .subject(entityId)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(federation.statementValidity)))
                .claim("jwks", publicJwks(federation.federationKey))
                .claim("authority_hints", federation.authorityHints)
                .claim("metadata", metadata(config, federation, entityId))
                .build()
        val jwt =
            SignedJWT(
                JWSHeader
                    .Builder(JWSAlgorithm.ES256)
                    .keyID(federation.federationKey.keyID)
                    .type(JOSEObjectType(ENTITY_STATEMENT_TYP))
                    .build(),
                claims,
            )
        jwt.sign(ECDSASigner(federation.federationKey))
        return jwt.serialize()
    }

    private fun metadata(
        config: RelyingPartyConfiguration,
        federation: RpFederationConfig,
        entityId: String,
    ): Map<String, Any> =
        mapOf(
            "federation_entity" to
                buildMap {
                    put("organization_name", federation.organizationName)
                    put("homepage_uri", entityId)
                    if (federation.contacts.isNotEmpty()) put("contacts", federation.contacts)
                },
            "openid_credential_verifier" to
                mapOf(
                    "application_type" to "web",
                    "client_id" to entityId,
                    "client_name" to federation.organizationName,
                    // Published as the endpoint BASES while actual URIs append the
                    // transaction id: whether wallets match these lists exactly or by
                    // prefix is only observable against a real federation — tracked with
                    // the onboarding work (docs/note-divergenze.md, gap 2).
                    "request_uris" to listOf(config.endpoints.requestUriBase),
                    "response_uris" to listOf(config.endpoints.responseUriBase),
                    "vp_formats_supported" to
                        mapOf(
                            "dc+sd-jwt" to
                                mapOf(
                                    "sd-jwt_alg_values" to listOf("ES256", "ES384", "ES512"),
                                    "kb-jwt_alg_values" to listOf("ES256"),
                                ),
                        ),
                    "authorization_encrypted_response_alg" to RESPONSE_ENCRYPTION_ALG,
                    "encrypted_response_enc_values_supported" to ACCEPTED_RESPONSE_ENCS,
                    // The SAME published JWKs as the request object's client_metadata:
                    // a wallet resolving us through the federation must find the very key
                    // it is asked to encrypt to (matching kid, and use "enc").
                    "jwks" to
                        mapOf(
                            "keys" to
                                listOf(
                                    config.keys.requestSigningKey
                                        .toPublicJWK()
                                        .toJSONObject(),
                                    publicEncryptionJwk(config).toJSONObject(),
                                ),
                        ),
                ),
        )

    private fun publicJwks(key: ECKey): Map<String, Any> = mapOf("keys" to listOf(key.toPublicJWK().toJSONObject()))

    const val ENTITY_STATEMENT_TYP = "entity-statement+jwt"
    const val WELL_KNOWN_PATH = "/.well-known/openid-federation"
    const val MEDIA_TYPE = "application/entity-statement+jwt"
}
