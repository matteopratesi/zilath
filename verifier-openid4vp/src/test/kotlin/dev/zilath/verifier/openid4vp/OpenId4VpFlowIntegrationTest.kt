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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.ClaimPathSegment
import dev.zilath.verifier.core.CredentialVerifier
import dev.zilath.verifier.core.RawPresentation
import dev.zilath.verifier.core.RejectionReason
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TestVectors
import dev.zilath.verifier.core.VerificationContext
import dev.zilath.verifier.core.VerificationResult
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.time.Duration

class OpenId4VpFlowIntegrationTest : FlowTestSupport() {
    @Test
    fun `full cross-device flow ends verified with the disclosed claims`() {
        val started = startForPid()
        assertThat(started.qrPayload).startsWith("openid4vp://authorize?client_id=")
        assertThat(started.qrPayload).contains("request_uri=")
        val outcome = flow.handleWalletResponse(started.id, walletBody(started)).outcome
        assertThat(outcome).isInstanceOf(FlowOutcome.Verified::class.java)
        val claims = (outcome as FlowOutcome.Verified).claims.claims
        assertThat(claims["given_name"]?.jsonPrimitive?.content).isEqualTo("Ada")
        assertThat(flow.awaitOutcome(started.id)).isEqualTo(outcome)
    }

    @Test
    fun `the verifier is told which claims the query asked for`() {
        // Enforcing them is the verifier's job; handing them over is the flow's. Before the
        // fourth internal review nothing on the response path read the query's claims.
        val seen = mutableListOf<VerificationContext>()
        val recording =
            object : CredentialVerifier {
                private val real = SdJwtVcCredentialVerifier()

                override fun verify(
                    presentation: RawPresentation,
                    ctx: VerificationContext,
                ): VerificationResult = real.verify(presentation, ctx).also { seen += ctx }
            }
        val recordingFlow = OpenId4VpVerificationFlow.withInMemoryStore(config, recording, clock)
        val request = PresentationRequest.forTestPid("urn:zilath:test:entitlement")
        val started = recordingFlow.start(request)
        val jar = SignedJWT.parse(checkNotNull(recordingFlow.requestJwtFor(started.id)))
        val compact = TestVectors.vector(nonce = jar.jwtClaimsSet.getStringClaim("nonce"), audience = config.clientId)
        val payload =
            buildJsonObject {
                put("vp_token", buildJsonObject { put("pid", buildJsonArray { add(JsonPrimitive(compact)) }) })
                put("state", jar.jwtClaimsSet.getStringClaim("state"))
            }
        val jwe = JWEObject(JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM), Payload(payload.toString()))
        jwe.encrypt(
            ECDHEncrypter(advertisedEncryptionKey(jar.jwtClaimsSet.getJSONObjectClaim("client_metadata")).toECKey()),
        )
        recordingFlow.handleWalletResponse(started.id, DirectPostBody(mapOf("response" to jwe.serialize()))).outcome

        assertThat(seen.single().requestedClaims).isEqualTo(request.requestedClaims())
        assertThat(
            seen
                .single()
                .requestedClaims!!
                .claims
                .map { it.path },
        ).containsExactly(listOf(ClaimPathSegment.Key("given_name")), listOf(ClaimPathSegment.Key("family_name")))
        assertThat(seen.single().expectedVcts).containsExactly("urn:zilath:test:entitlement")
    }

    @Test
    fun `a credential of another type than the query asked for is rejected by the flow`() {
        // The type check lives in verifier-core; in the protocol it works only because the
        // flow hands it the query's vct_values. Every other presentation in this class uses
        // the requested type, so without this test the wiring could go and nothing notice.
        val started = startForPid()
        val outcome =
            flow.handleWalletResponse(started.id, walletBody(started, vct = "urn:zilath:test:something-else")).outcome
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.UNSUPPORTED_FORMAT)
    }

    @Test
    fun `a nonce echoed in the response must be the transaction's`() {
        val wrong = startForPid()
        val rejected = flow.handleWalletResponse(wrong.id, walletBody(wrong, echoedNonce = "wrong-nonce")).outcome
        assertThat((rejected as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.MALFORMED)
        assertThat(rejected.detail).isEqualTo("response nonce does not match the transaction")

        val right = startForPid()
        val nonce = SignedJWT.parse(flow.requestJwtFor(right.id)).jwtClaimsSet.getStringClaim("nonce")
        assertThat(flow.handleWalletResponse(right.id, walletBody(right, echoedNonce = nonce)).outcome)
            .isInstanceOf(FlowOutcome.Verified::class.java)
    }

    @Test
    fun `profile names are the specification line, not a patch release`() {
        // These strings reach an integrator's logs and configuration. Pinning them here
        // means a rename has to be a deliberate act rather than a side effect of editing
        // a comment — and naming the LINE keeps them true across 1.4.x, whose RP flow
        // requirements do not change between patch releases.
        assertThat(ItWalletProfile.name).isEqualTo("it-wallet-1.4")
        assertThat(ArfBaselineProfile.name).isEqualTo("arf-baseline")
    }

    @Test
    fun `request object follows the IT-Wallet v1_4 profile`() {
        val started = startForPid()
        val jwt = SignedJWT.parse(flow.requestJwtFor(started.id))
        assertThat(jwt.header.type.toString()).isEqualTo("oauth-authz-req+jwt")
        val claims = jwt.jwtClaimsSet
        assertThat(claims.getStringClaim("response_mode")).isEqualTo("direct_post.jwt")
        assertThat(claims.getStringClaim("response_type")).isEqualTo("vp_token")
        assertThat(claims.getStringClaim("client_id")).isEqualTo(config.clientId)
        assertThat(claims.getStringClaim("nonce").length).isGreaterThanOrEqualTo(32)
        assertThat(claims.getJSONObjectClaim("dcql_query")["credentials"]).isNotNull()
        assertThat(claims.getStringClaim("response_uri"))
            .isEqualTo("https://rp.example/openid4vp/response/${started.id.value}")
        val advertisedKey = advertisedEncryptionKey(claims.getJSONObjectClaim("client_metadata"))
        assertThat(advertisedKey.algorithm?.name).isEqualTo("ECDH-ES")
    }

    @Test
    fun `request object is addressed to the wallet audience and expires with the transaction`() {
        val started = startForPid()
        clock.advance(Duration.ofMinutes(1))
        val jwt = SignedJWT.parse(flow.requestJwtFor(started.id))
        assertThat(jwt.jwtClaimsSet.audience).containsExactly("https://self-issued.me/v2")
        // exp is bound to the transaction creation, not to the fetch instant.
        assertThat(jwt.jwtClaimsSet.expirationTime.toInstant())
            .isEqualTo(TestVectors.NOW.plus(Duration.ofMinutes(5)))
    }

    @Test
    fun `a throwing status checker ends in a terminal internal error, not a stuck transaction`() {
        val throwingStatus = StatusChecker { _, _ -> error("status backend down") }
        val fragileFlow =
            OpenId4VpVerificationFlow.withInMemoryStore(
                config.copy(statusChecker = throwingStatus),
                SdJwtVcCredentialVerifier(),
                clock,
            )
        val started = fragileFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        val jar = checkNotNull(fragileFlow.requestJwtFor(started.id))
        val claims = SignedJWT.parse(jar).jwtClaimsSet
        val compact =
            TestVectors.vector(
                nonce = claims.getStringClaim("nonce"),
                audience = config.clientId,
                statusUri = "https://status.example/1",
                statusIndex = 3,
            )
        val payload =
            buildJsonObject {
                put("vp_token", buildJsonObject { put("pid", buildJsonArray { add(compact) }) })
                put("state", claims.getStringClaim("state"))
            }
        val jwe = JWEObject(JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM), Payload(payload.toString()))
        jwe.encrypt(ECDHEncrypter(encryptionKey.toPublicJWK().toECKey()))
        val outcome =
            fragileFlow
                .handleWalletResponse(
                    started.id,
                    DirectPostBody(mapOf("response" to jwe.serialize())),
                ).outcome
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.INTERNAL_ERROR)
        assertThat(outcome.detail).doesNotContain("status backend down")
        assertThat(fragileFlow.awaitOutcome(started.id)).isEqualTo(outcome)
    }

    @Test
    fun `keys outside the profile are rejected at configuration time`() {
        assertThatThrownBy { RpKeys(signingKey.toPublicJWK(), encryptionKey) }
            .isInstanceOf(IllegalArgumentException::class.java)
        val wrongCurve = ECKeyGenerator(Curve.P_384).keyID("p384").generate()
        assertThatThrownBy { RpKeys(wrongCurve, encryptionKey) }
            .isInstanceOf(IllegalArgumentException::class.java)
        val missingKid = ECKeyGenerator(Curve.P_256).generate()
        assertThatThrownBy { RpKeys(missingKid, encryptionKey) }
            .isInstanceOf(IllegalArgumentException::class.java)
    }

    @Test
    fun `configuration toString never contains private key material`() {
        assertThat(config.toString()).doesNotContain(signingKey.d.toString())
        assertThat(config.toString()).doesNotContain(encryptionKey.d.toString())
    }

    @Test
    fun `a second response for the same transaction is rejected as replay`() {
        val started = startForPid()
        val body = walletBody(started)
        assertThat(flow.handleWalletResponse(started.id, body).outcome).isInstanceOf(FlowOutcome.Verified::class.java)
        val replayed = flow.handleWalletResponse(started.id, body).outcome
        assertThat(replayed).isInstanceOf(FlowOutcome.Rejected::class.java)
        assertThat((replayed as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.REPLAY)
        assertThat(flow.awaitOutcome(started.id)).isInstanceOf(FlowOutcome.Verified::class.java)
    }

    @Test
    fun `state mismatch is rejected as malformed`() {
        val started = startForPid()
        val outcome = flow.handleWalletResponse(started.id, walletBody(started, stateOverride = "someone-else")).outcome
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.MALFORMED)
    }

    @Test
    fun `wrong nonce in the presentation is rejected end to end`() {
        val started = startForPid()
        val outcome = flow.handleWalletResponse(started.id, walletBody(started, nonceOverride = "stolen-nonce")).outcome
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.NONCE_MISMATCH)
    }

    @Test
    fun `unknown transactions yield unknown outcomes and no request object`() {
        val ghost = TransactionId("does-not-exist")
        assertThat(flow.handleWalletResponse(ghost, DirectPostBody(emptyMap())).outcome).isEqualTo(FlowOutcome.Unknown)
        assertThat(flow.awaitOutcome(ghost)).isEqualTo(FlowOutcome.Unknown)
        assertThat(flow.requestJwtFor(ghost)).isNull()
    }

    @Test
    fun `request object is no longer served once the transaction is consumed`() {
        val started = startForPid()
        flow.handleWalletResponse(started.id, walletBody(started)).outcome
        assertThat(flow.requestJwtFor(started.id)).isNull()
    }

    @Test
    fun `the ARF baseline profile completes the flow with plain direct_post`() {
        val arfConfig = config.copy(profile = ArfBaselineProfile)
        val arfFlow = OpenId4VpVerificationFlow.withInMemoryStore(arfConfig, SdJwtVcCredentialVerifier(), clock)
        val started = arfFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        val jwt = SignedJWT.parse(arfFlow.requestJwtFor(started.id))
        assertThat(jwt.jwtClaimsSet.getStringClaim("response_mode")).isEqualTo("direct_post")
        val compact =
            TestVectors.vector(
                nonce = jwt.jwtClaimsSet.getStringClaim("nonce"),
                audience = config.clientId,
            )
        val outcome =
            arfFlow
                .handleWalletResponse(
                    started.id,
                    DirectPostBody(mapOf("vp_token" to compact, "state" to started.id.value)),
                ).outcome
        assertThat(outcome).isInstanceOf(FlowOutcome.Verified::class.java)
    }

    @Test
    fun `a wallet error response is acknowledged and terminal`() {
        val started = startForPid()
        val body = DirectPostBody(mapOf("error" to "access_denied", "error_description" to "user cancelled"))
        val outcome = flow.handleWalletResponse(started.id, body).outcome
        assertThat(outcome).isEqualTo(FlowOutcome.WalletErrorAcknowledged("access_denied", "user cancelled"))
        assertThat(flow.awaitOutcome(started.id)).isEqualTo(outcome)
        val afterwards = flow.handleWalletResponse(started.id, DirectPostBody(emptyMap())).outcome
        assertThat((afterwards as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.REPLAY)
    }

    @Test
    fun `pending transaction reports pending`() {
        val started = startForPid()
        assertThat(flow.awaitOutcome(started.id)).isEqualTo(FlowOutcome.Pending)
    }

    @Test
    fun `both forms of our own identifier are accepted as key binding audience`() {
        // A verifier identified with a Client Identifier Prefix: OpenID4VP says the
        // audience carries the prefix, the IT-Wallet rules read as the stripped form.
        // Wallets exist on both readings (pagopa/wallet-conformance-test#221).
        val prefixed =
            config.copy(
                clientId = OPENID_FEDERATION_PREFIX + TestVectors.AUDIENCE,
                federation =
                    RpFederationConfig(
                        entityId = TestVectors.AUDIENCE,
                        federationKey = ECKeyGenerator(Curve.P_256).keyID("fed").generate(),
                        authorityHints = listOf("https://ta.example"),
                        organizationName = "Test RP",
                    ),
            )
        val prefixedFlow = OpenId4VpVerificationFlow.withInMemoryStore(prefixed, SdJwtVcCredentialVerifier(), clock)

        fun present(audience: String): FlowOutcome {
            val started = prefixedFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
            val jar = SignedJWT.parse(checkNotNull(prefixedFlow.requestJwtFor(started.id)))
            val claims = jar.jwtClaimsSet
            val compact = TestVectors.vector(nonce = claims.getStringClaim("nonce"), audience = audience)
            val payload =
                buildJsonObject {
                    put("vp_token", buildJsonObject { put("pid", buildJsonArray { add(JsonPrimitive(compact)) }) })
                    put("state", JsonPrimitive(claims.getStringClaim("state")))
                }
            val advertised = advertisedEncryptionKey(claims.getJSONObjectClaim("client_metadata"))
            val jwe =
                JWEObject(
                    JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM),
                    com.nimbusds.jose.Payload(payload.toString()),
                )
            jwe.encrypt(ECDHEncrypter(advertised.toECKey()))
            return prefixedFlow
                .handleWalletResponse(
                    started.id,
                    DirectPostBody(mapOf("response" to jwe.serialize())),
                ).outcome
        }

        assertThat(present(prefixed.clientId)).isInstanceOf(FlowOutcome.Verified::class.java)
        assertThat(present(TestVectors.AUDIENCE)).isInstanceOf(FlowOutcome.Verified::class.java)
        // ...but only OUR identifier: another verifier's is still refused.
        val foreign = present("https://someone-else.example/zilath")
        assertThat(foreign).isInstanceOf(FlowOutcome.Rejected::class.java)
        assertThat((foreign as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.AUDIENCE_MISMATCH)
    }

    @Test
    fun `the accepted audience forms follow the client id prefix`() {
        assertThat(acceptedAudiencesFor(TestVectors.AUDIENCE)).containsExactly(TestVectors.AUDIENCE)
        assertThat(acceptedAudiencesFor(OPENID_FEDERATION_PREFIX + "https://rp.example"))
            .containsExactlyInAnyOrder("openid_federation:https://rp.example", "https://rp.example")
        assertThat(acceptedAudiencesFor("x509_hash:AbC123"))
            .containsExactlyInAnyOrder("x509_hash:AbC123", "AbC123")
        // A prefix with nothing after it yields no second form to accept.
        assertThat(acceptedAudiencesFor(OPENID_FEDERATION_PREFIX)).containsExactly(OPENID_FEDERATION_PREFIX)
    }
}
