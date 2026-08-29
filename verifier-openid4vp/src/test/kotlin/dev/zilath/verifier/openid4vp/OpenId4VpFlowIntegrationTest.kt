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
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.CredentialStatus
import dev.zilath.verifier.core.RejectionReason
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TestVectors
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
                    sameDeviceCallbackBase = "https://rp.example/cb",
                ),
            keys = RpKeys(requestSigningKey = signingKey, responseEncryptionKey = encryptionKey),
            trustEvaluator = TestVectors.trustIssuerEc(),
            statusChecker = StatusChecker { _, _ -> CredentialStatus.VALID },
        )
    private val flow =
        OpenId4VpVerificationFlow.withInMemoryStore(config, SdJwtVcCredentialVerifier(), clock)

    /**
     * Simulated wallet: fetches the request object exactly like a wallet would, verifies
     * its signature, then answers with an SD-JWT VC presentation encrypted to the RP key
     * advertised in `client_metadata` (IT-Wallet `direct_post.jwt` profile).
     */
    @Suppress("LongParameterList") // test factory: independent, defaulted axes
    private fun walletBody(
        started: StartedTransaction,
        nonceOverride: String? = null,
        stateOverride: String? = null,
        vpTokenAsPlainString: Boolean = false,
        encryptTo: JWK? = null,
        audienceOverride: String? = null,
    ): DirectPostBody {
        val jar = checkNotNull(flow.requestJwtFor(started.id)) { "request JWT not available" }
        val jwt = SignedJWT.parse(jar)
        assertThat(jwt.verify(ECDSAVerifier(signingKey.toPublicJWK()))).isTrue()
        val claims = jwt.jwtClaimsSet
        val advertisedKey = advertisedEncryptionKey(claims.getJSONObjectClaim("client_metadata"))
        val compact =
            TestVectors.vector(
                nonce = nonceOverride ?: claims.getStringClaim("nonce"),
                audience = audienceOverride ?: config.clientId,
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
        flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))

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
    fun `a recorded outcome outlives the transaction only as a claim-free tombstone`() {
        // This asserted that a Verified outcome, claims and all, stayed readable after the
        // transaction expired — so a checkout that polled late still got them. That is the
        // retention the privacy document promises not to have: the time to live is the
        // bound, and letting a late poll exceed it empties the promise.
        //
        // The transaction still answers after expiry, so "expired" stays distinguishable
        // from "never existed". What it no longer answers with is the claims.
        val started = startForPid()
        flow.handleWalletResponse(started.id, walletBody(started))
        clock.advance(Duration.ofMinutes(6))
        val outcome = flow.awaitOutcome(started.id)
        assertThat(outcome).isNotInstanceOf(FlowOutcome.Verified::class.java)
        assertThat(outcome.toString()).doesNotContain("given_name").doesNotContain("family_name")
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
            arfFlow.handleWalletResponse(
                started.id,
                DirectPostBody(mapOf("vp_token" to compact, "state" to started.id.value)),
            )
        assertThat(outcome).isInstanceOf(FlowOutcome.Verified::class.java)
    }

    @Test
    fun `a wallet error response is acknowledged and terminal`() {
        val started = startForPid()
        val body = DirectPostBody(mapOf("error" to "access_denied", "error_description" to "user cancelled"))
        val outcome = flow.handleWalletResponse(started.id, body)
        assertThat(outcome).isEqualTo(FlowOutcome.WalletErrorAcknowledged("access_denied", "user cancelled"))
        assertThat(flow.awaitOutcome(started.id)).isEqualTo(outcome)
        val afterwards = flow.handleWalletResponse(started.id, DirectPostBody(emptyMap()))
        assertThat((afterwards as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.REPLAY)
    }

    @Test
    fun `an error post cannot collect the return ticket of a verification it did not make`() {
        // The attack this test exists for. A same-device verification completes: the
        // wallet has answered, the outcome is Verified, and the user's browser has not yet
        // come back through the callback. An attacker who knows only the transaction id —
        // it travels in the URL the user was sent to — posts an unauthenticated error.
        //
        // Before the fix, that request was acknowledged with a body carrying the victim's
        // freshly minted response_code: one unauthenticated POST bought somebody else's
        // verified entitlement, and burned their return leg on the way out.
        val started = flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val verified = flow.handleWalletResponse(started.id, walletBody(started))
        assertThat(verified).isInstanceOf(FlowOutcome.Verified::class.java)

        val attacker = flow.handleWalletResponse(started.id, DirectPostBody(mapOf("error" to "access_denied")))
        assertThat(attacker).isInstanceOf(FlowOutcome.WalletErrorAcknowledged::class.java)

        // The attacker is owed an acknowledgement, and nothing else.
        assertThat(flow.sameDeviceRedirectFor(started.id, attacker)).isNull()

        // The verification itself is untouched: the wallet's own ack still carries the
        // ticket, and the user completes the flow they started.
        val redirect = checkNotNull(flow.sameDeviceRedirectFor(started.id, verified))
        val code = redirect.substringAfter("response_code=")
        assertThat(flow.consumeResponseCode(started.id, code)).isTrue()
    }

    @Test
    fun `a wallet error while the transaction is still open still returns the user`() {
        // The legitimate case the fix must not break (RPR-59): the user cancels inside the
        // wallet, the wallet posts an error, and the acknowledgement must still bring them
        // back to the relying party rather than stranding them.
        val started = flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val cancelled = flow.handleWalletResponse(started.id, DirectPostBody(mapOf("error" to "access_denied")))
        assertThat(flow.sameDeviceRedirectFor(started.id, cancelled)).contains("response_code=")
    }

    @Test
    fun `pending transaction reports pending`() {
        val started = startForPid()
        assertThat(flow.awaitOutcome(started.id)).isEqualTo(FlowOutcome.Pending)
    }

    @Test
    fun `an unreturned same-device outcome expires instead of leaking`() {
        val started = flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val outcome =
            flow.handleWalletResponse(started.id, DirectPostBody(mapOf("error" to "access_denied")))
        assertThat(outcome).isInstanceOf(FlowOutcome.WalletErrorAcknowledged::class.java)
        val redirect = checkNotNull(flow.sameDeviceRedirectFor(started.id, outcome))
        val code = redirect.substringAfter("response_code=")
        // The user never comes back within the transaction TTL.
        clock.advance(config.transactionTimeToLive.plusSeconds(1))
        // No new code is minted for an expired transaction.
        assertThat(flow.sameDeviceRedirectFor(started.id, outcome)).isNull()
        // The stale code is not consumable, and the wallet outcome is never exposed:
        // Expired while the entry survives, Unknown once the store sweep removed it.
        assertThat(flow.awaitOutcome(started.id)).isEqualTo(FlowOutcome.Expired)
        assertThat(flow.consumeResponseCode(started.id, code)).isFalse()
        assertThat(flow.awaitOutcome(started.id)).isIn(FlowOutcome.Expired, FlowOutcome.Unknown)
    }

    @Test
    fun `a retaining store still refuses to consume an expired response code`() {
        // A shared store may RETAIN expired entries: expiry must be a precondition of
        // consumption itself, not a side effect of the in-memory sweep.
        val retaining =
            object : TransactionStore {
                // The interface contract makes compareAndUpdate atomic: even a test
                // double must honor it, or the exactly-once code exchange is untested.
                val lock = Any()
                val entries = HashMap<TransactionId, Transaction>()

                override fun put(transaction: Transaction) {
                    synchronized(lock) { entries[transaction.id] = transaction }
                }

                override fun get(id: TransactionId): Transaction? = synchronized(lock) { entries[id] }

                override fun compareAndUpdate(
                    id: TransactionId,
                    update: (Transaction) -> Transaction,
                ): Transaction? =
                    synchronized(lock) {
                        entries[id]?.also { entries[id] = update(it) }
                    }

                override fun remove(id: TransactionId) {
                    synchronized(lock) { entries.remove(id) }
                }
            }
        val retainingFlow = OpenId4VpVerificationFlow(config, SdJwtVcCredentialVerifier(), retaining, clock)
        val started =
            retainingFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val cancelled =
            retainingFlow.handleWalletResponse(started.id, DirectPostBody(mapOf("error" to "access_denied")))
        val code =
            checkNotNull(retainingFlow.sameDeviceRedirectFor(started.id, cancelled)).substringAfter("response_code=")
        clock.advance(config.transactionTimeToLive.plusSeconds(1))
        // The retained entry is findable, but the stale code must not complete the flow.
        assertThat(retainingFlow.consumeResponseCode(started.id, code)).isFalse()
        assertThat(retainingFlow.awaitOutcome(started.id)).isEqualTo(FlowOutcome.Expired)
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
            return prefixedFlow.handleWalletResponse(started.id, DirectPostBody(mapOf("response" to jwe.serialize())))
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
