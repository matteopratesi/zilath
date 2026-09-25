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
package dev.zilath.verifier.trust

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import dev.zilath.verifier.core.IssuerTrustInput
import dev.zilath.verifier.core.TestVectors
import dev.zilath.verifier.core.TrustDecision
import org.assertj.core.api.Assertions.assertThat
import java.time.Clock
import java.time.ZoneOffset
import java.util.Date

/**
 * An in-memory three-level federation: trust anchor -> optional intermediate ->
 * credential issuer leaf. The leaf signs credentials with [TestVectors.issuerEcKey],
 * so SD-JWT VC vectors verify end-to-end against this federation.
 */
object FederationFixtures {
    const val ANCHOR_ID = "https://ta.example"
    const val INTERMEDIATE_ID = "https://int.example"
    const val LEAF_ID = TestVectors.ISSUER

    val anchorKey: ECKey = ECKeyGenerator(Curve.P_256).keyID("ta-fed").generate()
    val intermediateKey: ECKey = ECKeyGenerator(Curve.P_256).keyID("int-fed").generate()
    val leafFederationKey: ECKey = ECKeyGenerator(Curve.P_256).keyID("leaf-fed").generate()

    fun anchorConfig() = TrustAnchorConfig(ANCHOR_ID, listOf(anchorKey.toPublicJWK()))

    @Suppress("LongParameterList") // test factory: every parameter is an independent, defaulted axis
    fun signedStatement(
        signer: ECKey,
        iss: String,
        sub: String,
        expiresInSeconds: Long = 3600,
        typ: String = "entity-statement+jwt",
        configure: JWTClaimsSet.Builder.() -> Unit = {},
    ): String {
        val claims =
            JWTClaimsSet
                .Builder()
                .issuer(iss)
                .subject(sub)
                .issueTime(Date.from(TestVectors.NOW.minusSeconds(600)))
                .expirationTime(Date.from(TestVectors.NOW.plusSeconds(expiresInSeconds)))
                .apply(configure)
                .build()
        val jwt =
            com.nimbusds.jwt
                .SignedJWT(
                    JWSHeader
                        .Builder(JWSAlgorithm.ES256)
                        .keyID(signer.keyID)
                        .type(JOSEObjectType(typ))
                        .build(),
                    claims,
                )
        jwt.sign(ECDSASigner(signer))
        return jwt.serialize()
    }

    /**
     * Signs [payload] as it is, for documents the claims-set builder cannot express: an
     * explicit JSON `null` member, which the builder may drop.
     */
    fun signedRawStatement(
        signer: ECKey,
        payload: String,
    ): String {
        val jws =
            com.nimbusds.jose.JWSObject(
                JWSHeader
                    .Builder(JWSAlgorithm.ES256)
                    .keyID(signer.keyID)
                    .type(JOSEObjectType("entity-statement+jwt"))
                    .build(),
                com.nimbusds.jose.Payload(payload),
            )
        jws.sign(ECDSASigner(signer))
        return jws.serialize()
    }

    /** `"iat":…,"exp":…` for a raw payload, with the same window [signedStatement] uses. */
    fun rawValidityWindow(): String =
        """"iat":${TestVectors.NOW.minusSeconds(
            600,
        ).epochSecond},"exp":${TestVectors.NOW.plusSeconds(3600).epochSecond}"""

    fun jwksClaim(vararg keys: JWK): Map<String, Any> = mapOf("keys" to keys.map { it.toPublicJWK().toJSONObject() })

    /** The leaf's `openid_credential_issuer` section: its credential keys plus [extra] parameters. */
    fun credentialIssuerSection(vararg extra: Pair<String, Any?>): Map<String, Any?> =
        mapOf("jwks" to jwksClaim(TestVectors.issuerEcKey)) + extra

    fun leafConfiguration(
        authorityHint: String = ANCHOR_ID,
        includeCredentialKeys: Boolean = true,
        federationKey: ECKey = leafFederationKey,
        metadata: Map<String, Any?>? =
            if (includeCredentialKeys) mapOf("openid_credential_issuer" to credentialIssuerSection()) else null,
    ): String =
        signedStatement(federationKey, LEAF_ID, LEAF_ID) {
            claim("jwks", jwksClaim(federationKey))
            claim("authority_hints", listOf(authorityHint))
            if (metadata != null) claim("metadata", metadata)
        }

    /** The anchor's statement about the leaf, attesting its federation key, plus [configure]. */
    fun anchorStatementAboutLeaf(configure: JWTClaimsSet.Builder.() -> Unit = {}): String =
        signedStatement(anchorKey, ANCHOR_ID, LEAF_ID) {
            claim("jwks", jwksClaim(leafFederationKey))
            configure()
        }

    fun anchorConfiguration(fetchEndpoint: String = "$ANCHOR_ID/fetch"): String =
        signedStatement(anchorKey, ANCHOR_ID, ANCHOR_ID) {
            claim("jwks", jwksClaim(anchorKey))
            claim(
                "metadata",
                mapOf("federation_entity" to mapOf("federation_fetch_endpoint" to fetchEndpoint)),
            )
        }

    fun intermediateConfiguration(): String =
        signedStatement(intermediateKey, INTERMEDIATE_ID, INTERMEDIATE_ID) {
            claim("jwks", jwksClaim(intermediateKey))
            claim("authority_hints", listOf(ANCHOR_ID))
            claim(
                "metadata",
                mapOf("federation_entity" to mapOf("federation_fetch_endpoint" to "$INTERMEDIATE_ID/fetch")),
            )
        }

    /** Fetcher backed by a URL map; throws on anything not mapped. */
    fun fetcherOf(entries: Map<String, String>): FederationFetcher =
        FederationFetcher { url -> entries[url] ?: error("unmapped url: $url") }

    /** Direct federation: leaf directly under the anchor. */
    fun directFederation(): FederationFetcher =
        fetcherOf(
            mapOf(
                "$LEAF_ID/.well-known/openid-federation" to leafConfiguration(),
                "$ANCHOR_ID/.well-known/openid-federation" to anchorConfiguration(),
                "$ANCHOR_ID/fetch?sub=${encode(LEAF_ID)}" to
                    signedStatement(anchorKey, ANCHOR_ID, LEAF_ID) {
                        claim("jwks", jwksClaim(leafFederationKey))
                    },
            ),
        )

    /** Federation with an intermediate between leaf and anchor. */
    fun intermediatedFederation(): FederationFetcher =
        fetcherOf(
            mapOf(
                "$LEAF_ID/.well-known/openid-federation" to leafConfiguration(authorityHint = INTERMEDIATE_ID),
                "$INTERMEDIATE_ID/.well-known/openid-federation" to intermediateConfiguration(),
                "$ANCHOR_ID/.well-known/openid-federation" to anchorConfiguration(),
                "$INTERMEDIATE_ID/fetch?sub=${encode(LEAF_ID)}" to
                    signedStatement(intermediateKey, INTERMEDIATE_ID, LEAF_ID) {
                        claim("jwks", jwksClaim(leafFederationKey))
                    },
                "$ANCHOR_ID/fetch?sub=${encode(INTERMEDIATE_ID)}" to
                    signedStatement(anchorKey, ANCHOR_ID, INTERMEDIATE_ID) {
                        claim("jwks", jwksClaim(intermediateKey))
                    },
            ),
        )

    /** A valid offline trust chain (leaf EC + anchor statement about the leaf). */
    fun offlineChain(): List<String> =
        listOf(
            leafConfiguration(),
            signedStatement(anchorKey, ANCHOR_ID, LEAF_ID) {
                claim("jwks", jwksClaim(leafFederationKey))
            },
        )

    val clock: Clock = Clock.fixed(TestVectors.NOW, ZoneOffset.UTC)

    /**
     * An evaluator for tests about how a PROVIDED chain is validated: nothing it needs is
     * served, so everything it decides comes from the chain it is given.
     */
    fun chainEvaluator(anchor: TrustAnchorConfig = anchorConfig()): FederationTrustEvaluator =
        FederationTrustEvaluator(anchor, fetcherOf(emptyMap()), clock)

    fun inputFor(
        issuer: String? = LEAF_ID,
        trustChain: List<String> = emptyList(),
    ) = IssuerTrustInput(issuer = issuer, keyId = null, certificateChain = emptyList(), trustChain = trustChain)

    /** The kids of a Trusted decision's credential keys; fails the test on anything else. */
    fun trustedKeyIds(decision: TrustDecision): List<String?> {
        assertThat(decision).isInstanceOf(TrustDecision.Trusted::class.java)
        return (decision as TrustDecision.Trusted).issuerKeys.map { it.keyID }
    }

    /** The reason of an Untrusted decision; fails the test on anything else. */
    fun untrustedReason(decision: TrustDecision): String {
        assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
        return checkNotNull((decision as TrustDecision.Untrusted).reason)
    }

    /** The leaf's entity configuration with [configure] applied on top of the usual claims. */
    fun leafConfigurationWith(configure: JWTClaimsSet.Builder.() -> Unit): String =
        signedStatement(leafFederationKey, LEAF_ID, LEAF_ID) {
            claim("jwks", jwksClaim(leafFederationKey))
            claim("authority_hints", listOf(ANCHOR_ID))
            claim("metadata", mapOf("openid_credential_issuer" to credentialIssuerSection()))
            configure()
        }

    fun encode(value: String) =
        java.net.URLEncoder
            .encode(value, Charsets.UTF_8)
}
