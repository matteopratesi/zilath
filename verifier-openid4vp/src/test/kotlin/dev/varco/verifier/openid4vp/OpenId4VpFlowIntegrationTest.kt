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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.SignedJWT
import dev.varco.verifier.core.CredentialStatus
import dev.varco.verifier.core.RejectionReason
import dev.varco.verifier.core.SdJwtVcCredentialVerifier
import dev.varco.verifier.core.StatusChecker
import dev.varco.verifier.core.TestVectors
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.time.Duration

class OpenId4VpFlowIntegrationTest {
    private val signingKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate()
    private val encryptionKey = ECKeyGenerator(Curve.P_256).keyID("rp-enc").generate()
    private val clock = SteppingClock(TestVectors.NOW)
    private val config =
        RelyingPartyConfiguration(
            clientId = TestVectors.AUDIENCE,
            endpoints =
                RpEndpoints(
                    requestUriBase = "https://rp.example/openid4vp/request",
                    responseUriBase = "https://rp.example/openid4vp/response",
                ),
            keys = RpKeys(requestSigningKey = signingKey, responseEncryptionKey = encryptionKey),
            trustEvaluator = TestVectors.trustIssuerEc(),
            statusChecker = StatusChecker { CredentialStatus.VALID },
        )
    private val flow =
        OpenId4VpVerificationFlow.withInMemoryStore(config, SdJwtVcCredentialVerifier(), clock)

    /**
     * Simulated wallet: fetches the request object exactly like a wallet would, verifies
     * its signature, then answers with an SD-JWT VC presentation encrypted to the RP key
     * advertised in `client_metadata` (IT-Wallet `direct_post.jwt` profile).
     */
    private fun walletBody(
        started: StartedTransaction,
        nonceOverride: String? = null,
        stateOverride: String? = null,
        vpTokenAsPlainString: Boolean = false,
        encryptTo: JWK? = null,
    ): DirectPostBody {
        val jar = checkNotNull(flow.requestJwtFor(started.id)) { "request JWT not available" }
        val jwt = SignedJWT.parse(jar)
        assertThat(jwt.verify(ECDSAVerifier(signingKey.toPublicJWK()))).isTrue()
        val claims = jwt.jwtClaimsSet
        val advertisedKey = advertisedEncryptionKey(claims.getJSONObjectClaim("client_metadata"))
        val compact =
            TestVectors.vector(
                nonce = nonceOverride ?: claims.getStringClaim("nonce"),
                audience = config.clientId,
            )
        val payload =
            buildJsonObject {
                if (vpTokenAsPlainString) {
                    put("vp_token", JsonPrimitive(compact))
                } else {
                    put(
                        "vp_token",
                        buildJsonObject { put("pid", buildJsonArray { add(JsonPrimitive(compact)) }) },
                    )
                }
                put("state", stateOverride ?: claims.getStringClaim("state"))
            }
        val jwe = JWEObject(JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM), Payload(payload.toString()))
        jwe.encrypt(ECDHEncrypter((encryptTo ?: advertisedKey).toECKey()))
        return DirectPostBody(mapOf("response" to jwe.serialize()))
    }

    private fun advertisedEncryptionKey(clientMetadata: Map<String, Any?>): JWK {
        val jwks = clientMetadata["jwks"] as Map<*, *>
        val keys = jwks["keys"] as List<*>

        @Suppress("UNCHECKED_CAST")
        return JWK.parse(JSONObjectUtils.toJSONString(keys.first() as Map<String, Any?>))
    }

    private fun startForPid(): StartedTransaction =
        flow.start(PresentationRequest.forTestPid("urn:varco:test:entitlement"))

    @Test
    fun `full cross-device flow ends verified with the disclosed claims`() {
        val started = startForPid()
        assertThat(started.qrPayload).startsWith("openid4vp://authorize?client_id=")
        assertThat(started.qrPayload).contains("request_uri=")
        val outcome = flow.handleWalletResponse(started.id, walletBody(started))
        assertThat(outcome).isInstanceOf(FlowOutcome.Verified::class.java)
        val claims = (outcome as FlowOutcome.Verified).claims.claims
        assertThat(claims["given_name"]?.jsonPrimitive?.content).isEqualTo("Ada")
        assertThat(flow.awaitOutcome(started.id)).isEqualTo(outcome)
    }

    @Test
    fun `request object follows the IT-Wallet v1_4_5 profile`() {
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
    fun `a recorded outcome survives the transaction expiry`() {
        val started = startForPid()
        flow.handleWalletResponse(started.id, walletBody(started))
        clock.advance(Duration.ofMinutes(6))
        assertThat(flow.awaitOutcome(started.id)).isInstanceOf(FlowOutcome.Verified::class.java)
    }

    @Test
    fun `a throwing status checker ends in a terminal internal error, not a stuck transaction`() {
        val throwingStatus = StatusChecker { error("status backend down") }
        val fragileFlow =
            OpenId4VpVerificationFlow.withInMemoryStore(
                config.copy(statusChecker = throwingStatus),
                SdJwtVcCredentialVerifier(),
                clock,
            )
        val started = fragileFlow.start(PresentationRequest.forTestPid("urn:varco:test:entitlement"))
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
                put("vp_token", JsonPrimitive(compact))
                put("state", claims.getStringClaim("state"))
            }
        val jwe = JWEObject(JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM), Payload(payload.toString()))
        jwe.encrypt(ECDHEncrypter(encryptionKey.toPublicJWK().toECKey()))
        val outcome = fragileFlow.handleWalletResponse(started.id, DirectPostBody(mapOf("response" to jwe.serialize())))
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
        assertThat(flow.handleWalletResponse(started.id, body)).isInstanceOf(FlowOutcome.Verified::class.java)
        val replayed = flow.handleWalletResponse(started.id, body)
        assertThat(replayed).isInstanceOf(FlowOutcome.Rejected::class.java)
        assertThat((replayed as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.REPLAY)
        assertThat(flow.awaitOutcome(started.id)).isInstanceOf(FlowOutcome.Verified::class.java)
    }

    @Test
    fun `an expired transaction cannot complete`() {
        val started = startForPid()
        val body = walletBody(started)
        clock.advance(Duration.ofMinutes(6))
        assertThat(flow.awaitOutcome(started.id)).isEqualTo(FlowOutcome.Expired)
        assertThat(flow.handleWalletResponse(started.id, body)).isEqualTo(FlowOutcome.Expired)
        assertThat(flow.awaitOutcome(started.id)).isEqualTo(FlowOutcome.Unknown)
    }

    @Test
    fun `state mismatch is rejected as malformed`() {
        val started = startForPid()
        val outcome = flow.handleWalletResponse(started.id, walletBody(started, stateOverride = "someone-else"))
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.MALFORMED)
    }

    @Test
    fun `wrong nonce in the presentation is rejected end to end`() {
        val started = startForPid()
        val outcome = flow.handleWalletResponse(started.id, walletBody(started, nonceOverride = "stolen-nonce"))
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.NONCE_MISMATCH)
    }

    @Test
    fun `missing response parameter is rejected as malformed`() {
        val started = startForPid()
        val outcome = flow.handleWalletResponse(started.id, DirectPostBody(emptyMap()))
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.MALFORMED)
    }

    @Test
    fun `garbage response is rejected as malformed`() {
        val started = startForPid()
        val outcome = flow.handleWalletResponse(started.id, DirectPostBody(mapOf("response" to "not-a-jwe")))
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.MALFORMED)
    }

    @Test
    fun `response encrypted to the wrong key is rejected as malformed`() {
        val started = startForPid()
        val wrongKey = ECKeyGenerator(Curve.P_256).keyID("wrong").generate().toPublicJWK()
        val outcome = flow.handleWalletResponse(started.id, walletBody(started, encryptTo = wrongKey))
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.MALFORMED)
    }

    @Test
    fun `vp_token as a plain string is accepted`() {
        val started = startForPid()
        val outcome = flow.handleWalletResponse(started.id, walletBody(started, vpTokenAsPlainString = true))
        assertThat(outcome).isInstanceOf(FlowOutcome.Verified::class.java)
    }

    @Test
    fun `unknown transactions yield unknown outcomes and no request object`() {
        val ghost = TransactionId("does-not-exist")
        assertThat(flow.handleWalletResponse(ghost, DirectPostBody(emptyMap()))).isEqualTo(FlowOutcome.Unknown)
        assertThat(flow.awaitOutcome(ghost)).isEqualTo(FlowOutcome.Unknown)
        assertThat(flow.requestJwtFor(ghost)).isNull()
    }

    @Test
    fun `request object is no longer served once the transaction is consumed`() {
        val started = startForPid()
        flow.handleWalletResponse(started.id, walletBody(started))
        assertThat(flow.requestJwtFor(started.id)).isNull()
    }

    @Test
    fun `pending transaction reports pending`() {
        val started = startForPid()
        assertThat(flow.awaitOutcome(started.id)).isEqualTo(FlowOutcome.Pending)
    }
}
