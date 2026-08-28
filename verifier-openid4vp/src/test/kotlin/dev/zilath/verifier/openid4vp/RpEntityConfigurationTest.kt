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

import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.CredentialStatus
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.TrustEvaluator
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class RpEntityConfigurationTest {
    private val clock = Clock.fixed(Instant.parse("2026-08-27T21:00:00Z"), ZoneOffset.UTC)
    private val federationKey = ECKeyGenerator(Curve.P_256).keyID("rp-fed").generate()

    private fun config(clientId: String) =
        RelyingPartyConfiguration(
            clientId = clientId,
            endpoints = RpEndpoints("https://rp.example/openid4vp/request", "https://rp.example/openid4vp/response"),
            keys =
                RpKeys(
                    requestSigningKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate(),
                    responseEncryptionKey = ECKeyGenerator(Curve.P_256).keyID("rp-enc").generate(),
                ),
            trustEvaluator = TrustEvaluator { _ -> TrustDecision.Untrusted("static test evaluator") },
            statusChecker = StatusChecker { CredentialStatus.VALID },
            federation = federation(),
        )

    private fun federation(entityId: String = "https://rp.example") =
        RpFederationConfig(
            entityId = entityId,
            federationKey = federationKey,
            authorityHints = listOf("https://trust-anchor.example"),
            organizationName = "Teatro di Prova",
        )

    @Test
    fun `the entity configuration is a self-signed statement with both metadata types`() {
        val config = config("openid_federation:https://rp.example")
        val jwt = SignedJWT.parse(RpEntityConfiguration.build(config, config.federation!!, clock))
        assertThat(jwt.header.type.type).isEqualTo(RpEntityConfiguration.ENTITY_STATEMENT_TYP)
        assertThat(jwt.header.keyID).isEqualTo("rp-fed")
        assertThat(jwt.verify(ECDSAVerifier(federationKey.toECPublicKey()))).isTrue()
        val claims = jwt.jwtClaimsSet
        assertThat(claims.issuer).isEqualTo("https://rp.example")
        assertThat(claims.subject).isEqualTo("https://rp.example")
        assertThat(claims.getStringListClaim("authority_hints")).containsExactly("https://trust-anchor.example")
        val metadata = claims.getJSONObjectClaim("metadata")
        assertThat(metadata).containsKeys("federation_entity", "openid_credential_verifier")
    }

    @Test
    fun `the verifier metadata attests endpoints, formats and protocol keys`() {
        val config = config("openid_federation:https://rp.example")
        val jwt = SignedJWT.parse(RpEntityConfiguration.build(config, config.federation!!, clock))

        @Suppress("UNCHECKED_CAST")
        val verifier =
            jwt.jwtClaimsSet.getJSONObjectClaim("metadata")["openid_credential_verifier"] as Map<String, Any?>
        assertThat(verifier["application_type"]).isEqualTo("web")
        assertThat(verifier["client_id"]).isEqualTo("https://rp.example")
        assertThat(verifier["request_uris"]).isEqualTo(listOf("https://rp.example/openid4vp/request"))
        assertThat(verifier["response_uris"]).isEqualTo(listOf("https://rp.example/openid4vp/response"))
        assertThat(verifier["encrypted_response_enc_values_supported"]).isEqualTo(listOf("A256GCM", "A128GCM"))
        assertThat(verifier["authorization_encrypted_response_alg"]).isEqualTo("ECDH-ES")

        @Suppress("UNCHECKED_CAST")
        val formats = verifier["vp_formats_supported"] as Map<String, Any?>
        assertThat(formats).containsKey("dc+sd-jwt")

        @Suppress("UNCHECKED_CAST")
        val jwks = (verifier["jwks"] as Map<String, Any?>)["keys"] as List<Map<String, Any?>>
        assertThat(jwks.map { it["kid"] }).containsExactlyInAnyOrder("rp-sign", "rp-enc")
        // A wallet resolving us through the federation must find the encryption key it is
        // asked to use, flagged as such.
        assertThat(jwks.single { it["kid"] == "rp-enc" }["use"]).isEqualTo("enc")
        // Public halves only: private parameters must never be published.
        assertThat(jwks).allSatisfy { key -> assertThat(key).doesNotContainKey("d") }
    }

    @Test
    fun `the federation jwks never leaks private key material`() {
        val config = config("openid_federation:https://rp.example")
        val jwt = SignedJWT.parse(RpEntityConfiguration.build(config, config.federation!!, clock))

        @Suppress("UNCHECKED_CAST")
        val keys = jwt.jwtClaimsSet.getJSONObjectClaim("jwks")["keys"] as List<Map<String, Any?>>
        assertThat(keys.single()["kid"]).isEqualTo("rp-fed")
        assertThat(keys.single()).doesNotContainKey("d")
    }

    @Test
    fun `a federation-scheme client id must agree with the entity id`() {
        assertThatIllegalArgumentException()
            .isThrownBy { config("openid_federation:https://other.example") }
            .withMessageContaining("must agree")
    }

    @Test
    fun `a federation-scheme client id without federation data is refused`() {
        assertThatIllegalArgumentException()
            .isThrownBy { config("openid_federation:https://rp.example").copy(federation = null) }
            .withMessageContaining("requires a federation configuration")
    }

    @Test
    fun `lookalike localhost hosts and hostless urls are not valid entity ids`() {
        assertThatIllegalArgumentException()
            .isThrownBy { federation(entityId = "http://localhost.attacker.example") }
        assertThatIllegalArgumentException()
            .isThrownBy { federation(entityId = "https://") }
        // The exact localhost host, with a port, stays fine for development.
        assertThat(federation(entityId = "http://localhost:8080").entityId)
            .isEqualTo("http://localhost:8080")
    }

    @Test
    fun `authority hints must be valid entity ids and the validity must be positive`() {
        assertThatIllegalArgumentException()
            .isThrownBy {
                federation().copy(authorityHints = listOf("http://anchor.example"))
            }.withMessageContaining("authority hint")
        assertThatIllegalArgumentException()
            .isThrownBy {
                federation().copy(authorityHints = listOf("https://anchor.example#frag"))
            }.withMessageContaining("authority hint")
        assertThatIllegalArgumentException()
            .isThrownBy {
                federation().copy(statementValidity = java.time.Duration.ZERO)
            }.withMessageContaining("must be positive")
    }

    @Test
    fun `entity ids with a query or a fragment are refused`() {
        assertThatIllegalArgumentException()
            .isThrownBy { federation(entityId = "https://rp.example?tenant=a") }
        assertThatIllegalArgumentException()
            .isThrownBy { federation(entityId = "https://rp.example#fragment") }
    }

    @Test
    fun `an x509_hash client id can still publish an entity configuration`() {
        val config = config("x509_hash:AbC123")
        val jwt = SignedJWT.parse(RpEntityConfiguration.build(config, config.federation!!, clock))
        assertThat(jwt.jwtClaimsSet.subject).isEqualTo("https://rp.example")
    }

    @Test
    fun `the JAR carries the trust chain header when the federation provides one`() {
        val chain = listOf("eyJa.leaf.sig", "eyJa.anchor.sig")
        val base = config("openid_federation:https://rp.example")
        val withChain = base.copy(federation = federation().copy(trustChain = chain))
        val transaction =
            Transaction(
                id = TransactionId("tx-1"),
                nonce = "n".repeat(32),
                state = TransactionState.CREATED,
                createdAt = clock.instant(),
                request = PresentationRequest.forTestPid("urn:eudi:pid:it:1"),
            )
        val jar = SignedJWT.parse(buildRequestJwt(withChain, transaction, clock.instant()))
        assertThat(jar.header.getCustomParam("trust_chain")).isEqualTo(chain)
        val bare = SignedJWT.parse(buildRequestJwt(base, transaction, clock.instant()))
        assertThat(bare.header.getCustomParam("trust_chain")).isNull()
    }
}
