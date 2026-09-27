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
package dev.zilath.demo.cedsim

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.SignedJWT
import dev.zilath.demo.ConformanceController
import dev.zilath.demo.DemoCheckoutController
import dev.zilath.verifier.core.CredentialStatus
import dev.zilath.verifier.core.RejectionReason
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.openid4vp.DirectPostBody
import dev.zilath.verifier.openid4vp.FlowMode
import dev.zilath.verifier.openid4vp.FlowOutcome
import dev.zilath.verifier.openid4vp.OpenId4VpVerificationFlow
import dev.zilath.verifier.openid4vp.PresentationRequest
import dev.zilath.verifier.openid4vp.RelyingPartyConfiguration
import dev.zilath.verifier.openid4vp.RpEndpoints
import dev.zilath.verifier.openid4vp.RpKeys
import dev.zilath.verifier.openid4vp.TransactionId
import dev.zilath.verifier.openid4vp.VerificationReceipts
import dev.zilath.verifier.trust.FederationFetcher
import dev.zilath.verifier.trust.FederationTrustEvaluator
import dev.zilath.verifier.trust.TrustAnchorConfig
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.springframework.http.HttpHeaders
import org.springframework.mock.web.MockHttpServletRequest
import java.nio.file.Path
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class CedSimFlowTest {
    private val clock = Clock.fixed(Instant.parse("2026-08-25T10:00:00Z"), ZoneOffset.UTC)
    private val keys = CedSim.generateKeys()
    private val config =
        RelyingPartyConfiguration(
            clientId = "https://demo.zilath.example",
            endpoints =
                RpEndpoints(
                    "https://demo.zilath.example/req",
                    "https://demo.zilath.example/res",
                    sameDeviceCallbackBase = "https://demo.zilath.example/cb",
                ),
            keys =
                RpKeys(
                    requestSigningKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate(),
                    responseEncryptionKey = ECKeyGenerator(Curve.P_256).keyID("rp-enc").generate(),
                ),
            trustEvaluator =
                FederationTrustEvaluator(
                    TrustAnchorConfig(CedSim.ANCHOR_ID, listOf(keys.anchor.toPublicJWK())),
                    FederationFetcher { error("offline: the simulated chain travels in the header") },
                    clock,
                    offlineFallback = true,
                ),
            statusChecker = StatusChecker { _, _ -> CredentialStatus.VALID },
        )
    private val flow = OpenId4VpVerificationFlow.withInMemoryStore(config, SdJwtVcCredentialVerifier(), clock)
    private var lastStartedId: dev.zilath.verifier.openid4vp.TransactionId? = null
    private var lastPollToken: dev.zilath.verifier.openid4vp.PollToken? = null
    private var lastHandled: dev.zilath.verifier.openid4vp.HandledResponse? = null

    private fun encryptionKeyOf(clientMetadata: Map<String, Any?>): JWK {
        val jwks = clientMetadata["jwks"] as Map<*, *>
        val list = jwks["keys"] as List<*>

        @Suppress("UNCHECKED_CAST")
        return JWK.parse(JSONObjectUtils.toJSONString(list.first() as Map<String, Any?>))
    }

    private fun presentSimulatedCed(
        withKeys: CedSim.Keys,
        constantAttendanceAllowance: Boolean = true,
        expiryDate: String = "2030-12-31",
        mode: FlowMode = FlowMode.CROSS_DEVICE,
    ): FlowOutcome {
        val request = PresentationRequest.forVct(CedSim.VCT, CedSim.CLAIM_PATHS, CedSim.CREDENTIAL_QUERY_ID)
        val started = flow.start(request, mode)
        lastStartedId = started.id
        lastPollToken = started.pollToken
        val handled = answerWithCed(started.id, withKeys, constantAttendanceAllowance, expiryDate)
        lastHandled = handled
        return handled.outcome
    }

    /** The simulated wallet's answer to the request object of [txId]. */
    private fun answerWithCed(
        txId: TransactionId,
        withKeys: CedSim.Keys,
        constantAttendanceAllowance: Boolean = true,
        expiryDate: String = "2030-12-31",
    ): dev.zilath.verifier.openid4vp.HandledResponse {
        val jar = SignedJWT.parse(checkNotNull(flow.requestJwtFor(txId)))
        val claims = jar.jwtClaimsSet
        val presentation =
            CedSim.mintPresentation(
                withKeys,
                claims.getStringClaim("nonce"),
                claims.getStringClaim("client_id"),
                clock,
                constantAttendanceAllowance,
                expiryDate,
            )
        val response =
            CedSim.buildEncryptedResponse(
                claims.getStringClaim("state"),
                presentation,
                encryptionKeyOf(claims.getJSONObjectClaim("client_metadata")),
            )
        return flow.handleWalletResponse(txId, DirectPostBody(mapOf("response" to response)))
    }

    private fun demoController() =
        DemoCheckoutController(flow, VerificationReceipts(config, clock), clock, CedSim.VCT, "ced-sim")

    /** A purchase started from the demo page: its transaction, and the session cookie it set. */
    private fun startFromDemo(demo: DemoCheckoutController): Pair<TransactionId, String> {
        val response = demo.startEntitledPurchase("cross-device", null, MockHttpServletRequest())
        val txId = TransactionId(checkNotNull(response.headers.location).path.substringAfterLast('/'))
        val session =
            checkNotNull(response.headers.getFirst(HttpHeaders.SET_COOKIE))
                .substringAfter("${DemoCheckoutController.SESSION_COOKIE}=")
                .substringBefore(';')
        return txId to session
    }

    @Test
    fun `the demo pages show a verified card only to the browser that started it`() {
        // The transaction id is in the QR on the screen: whoever had seen it read the holder's
        // name and entitlement from the ticket page.
        val demo = demoController()
        val (txId, session) = startFromDemo(demo)
        assertThat(answerWithCed(txId, keys).outcome).isInstanceOf(FlowOutcome.Verified::class.java)
        for (bystander in listOf(null, startFromDemo(demo).second)) {
            val ticket = demo.ticket(txId.value, bystander)
            assertThat(ticket.statusCode.value()).isEqualTo(404)
            assertThat(ticket.body).doesNotContain("Maria")
            assertThat(demo.receipt(txId.value, bystander).statusCode.value()).isEqualTo(404)
            assertThat(demo.status(txId.value, bystander)).containsEntry("status", "unknown")
        }
        val owner = demo.ticket(txId.value, session)
        assertThat(owner.statusCode.value()).isEqualTo(200)
        assertThat(owner.body).contains("Maria")
    }

    @Test
    fun `a card without the entitlement gets a receipt that says so`() {
        // The first status poll used to sign the receipt, before the entitlement policy ran:
        // a card that verified without the entitlement was archived as one that had it.
        val demo = demoController()
        val (txId, session) = startFromDemo(demo)
        answerWithCed(txId, keys, constantAttendanceAllowance = false)
        assertThat(demo.status(txId.value, session)).containsEntry("status", "verified")
        val receipt = SignedJWT.parse(checkNotNull(demo.receipt(txId.value, session).body)).jwtClaimsSet
        assertThat(receipt.getStringClaim("outcome")).isEqualTo("verified")
        assertThat(receipt.getBooleanClaim("entitled")).isFalse()
        assertThat(demo.ticket(txId.value, session).statusCode.value()).isEqualTo(409)
    }

    @Test
    fun `the simulated CED unlocks the companion entitlement end to end`() {
        val outcome = presentSimulatedCed(keys)
        assertThat(outcome).isInstanceOf(FlowOutcome.Verified::class.java)
        val claims = (outcome as FlowOutcome.Verified).claims.claims
        assertThat(claims["constant_attendance_allowance"]?.jsonPrimitive?.boolean).isTrue()
        assertThat(claims["given_name"]?.jsonPrimitive?.content).isEqualTo("Maria")
        // The simulation discloses only the minimized subset: never the portrait or the
        // document number, and never conditions or subcategories.
        assertThat(claims.keys).doesNotContain("diagnosis", "art3c3", "percentage", "portrait", "document_number")
    }

    @Test
    fun `a valid card WITHOUT the entitlement verifies but does not grant the ticket`() {
        val outcome = presentSimulatedCed(keys, constantAttendanceAllowance = false)
        // The credential itself is cryptographically fine...
        assertThat(outcome).isInstanceOf(FlowOutcome.Verified::class.java)
        // ...but the checkout policy must refuse the benefit.
        val claims = (outcome as FlowOutcome.Verified).claims.claims
        assertThat(CedSim.entitlementGranted(claims, clock)).isFalse()
    }

    @Test
    fun `an expired card does not grant the ticket`() {
        val outcome = presentSimulatedCed(keys, expiryDate = "2026-08-24")
        val claims = (outcome as FlowOutcome.Verified).claims.claims
        assertThat(CedSim.entitlementGranted(claims, clock)).isFalse()
    }

    @Test
    fun `an entitled unexpired card grants the ticket`() {
        val outcome = presentSimulatedCed(keys)
        val claims = (outcome as FlowOutcome.Verified).claims.claims
        assertThat(CedSim.entitlementGranted(claims, clock)).isTrue()
    }

    @Test
    fun `the string true does not grant the entitlement`() {
        val forged =
            kotlinx.serialization.json.buildJsonObject {
                put("constant_attendance_allowance", kotlinx.serialization.json.JsonPrimitive("true"))
                put("expiry_date", kotlinx.serialization.json.JsonPrimitive("2030-12-31"))
            }
        assertThat(CedSim.entitlementGranted(forged, clock)).isFalse()
    }

    @Test
    fun `a simulated CED from an unknown federation is rejected`() {
        val impostorKeys = CedSim.generateKeys()
        val outcome = presentSimulatedCed(impostorKeys)
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.UNTRUSTED_ISSUER)
    }

    @Test
    fun `the same-device flow issues a single-use response code after verification`() {
        val outcome = presentSimulatedCed(keys, mode = FlowMode.SAME_DEVICE)
        assertThat(outcome).isInstanceOf(FlowOutcome.Verified::class.java)
        val txId = lastTransactionId()
        // The acknowledgement of the wallet's own response carries the return ticket.
        val redirect = checkNotNull(lastHandled).redirectUri
        assertThat(redirect).startsWith("https://demo.zilath.example/cb/${txId.value}?response_code=")
        // WP_094: same-device outcomes stay pending until the user-agent comes back.
        assertThat(flow.awaitOutcome(txId, checkNotNull(lastPollToken))).isEqualTo(FlowOutcome.Pending)
        val code = redirect!!.substringAfter("response_code=")
        // Presented on ANOTHER LIVE transaction the code is refused AND left intact —
        // an unknown id would prove nothing, since there is no entry to update.
        val other =
            flow.start(
                PresentationRequest.forVct(CedSim.VCT, CedSim.CLAIM_PATHS, CedSim.CREDENTIAL_QUERY_ID),
                FlowMode.SAME_DEVICE,
            )
        assertThat(flow.awaitOutcome(other.id, other.pollToken)).isEqualTo(FlowOutcome.Pending)
        assertThat(flow.consumeResponseCode(other.id, code)).isNull()
        // ...so its own return leg still completes, exactly once.
        val reader = checkNotNull(flow.consumeResponseCode(txId, code))
        assertThat(flow.consumeResponseCode(txId, code)).isNull()
        // A consumed code is never re-minted, and the outcome is now observable.
        assertThat(flow.handleWalletResponse(txId, DirectPostBody(mapOf("error" to "access_denied"))).redirectUri)
            .isNull()
        assertThat(flow.awaitOutcome(txId, reader)).isInstanceOf(FlowOutcome.Verified::class.java)
    }

    @Test
    fun `the conformance outcome endpoint reports the category and never the claims`() {
        // It used to answer awaitOutcome(...).toString(), and that data class carries the
        // disclosed claims: an unauthenticated GET with a transaction id returned somebody's
        // entitlement. The harness only ever needed to know whether the run passed.
        // Cross-device: a same-device outcome deliberately reads as pending until the
        // user-agent has come back through the response-code exchange (WP_094).
        val outcome = presentSimulatedCed(keys)
        assertThat(outcome).isInstanceOf(FlowOutcome.Verified::class.java)
        val body =
            ConformanceController(flow, config, clock, CedSim.VCT)
                .outcome(lastTransactionId().value, checkNotNull(lastPollToken).value)
        assertThat(body).containsEntry("outcome", "verified")
        // Nothing from inside the credential, not the claim names and not their values.
        assertThat(body.values.joinToString(" "))
            .doesNotContain("constant_attendance_allowance")
            .doesNotContain("expiry_date")
            .doesNotContain("true")
    }

    @Test
    fun `a same-device conformance run comes back through the demo callback`() {
        // The conformance endpoints started a transaction the demo's callback did not know,
        // so the user-agent coming back with the response code was turned away. A
        // cancellation is enough to show it: it earns the return ticket too.
        val conformance = ConformanceController(flow, config, clock, CedSim.VCT)
        val demo = DemoCheckoutController(flow, VerificationReceipts(config, clock), clock, CedSim.VCT, "ced-sim")
        val started = conformance.start()
        val txId = started.getValue("transactionId")
        val startToken = started.getValue("pollToken")
        val handled =
            flow.handleWalletResponse(TransactionId(txId), DirectPostBody(mapOf("error" to "access_denied")))
        val code = checkNotNull(handled.redirectUri).substringAfter("response_code=")
        assertThat(conformance.outcome(txId, startToken)).containsEntry("outcome", "pending")

        // Completed, and pointed at no ticket page: those read a transaction by its id alone.
        val returned = demo.sameDeviceCallback(txId, code, null, null)
        assertThat(returned.statusCode.value()).isEqualTo(200)
        assertThat(demo.status(txId, null)).containsEntry("status", "unknown")
        // The read right went with the user-agent that returned, which holds the token for it;
        // the start token reads nothing.
        val reader =
            Json
                .parseToJsonElement(checkNotNull(returned.body))
                .jsonObject
                .getValue("pollToken")
                .jsonPrimitive.content
        assertThat(conformance.outcome(txId, reader)).containsEntry("outcome", "wallet_error")
        assertThat(conformance.outcome(txId, startToken)).containsEntry("outcome", "unknown")
    }

    @Test
    fun `a cross-device transaction never yields a same-device redirect`() {
        val outcome = presentSimulatedCed(keys)
        assertThat(outcome).isInstanceOf(FlowOutcome.Verified::class.java)
        assertThat(checkNotNull(lastHandled).redirectUri).isNull()
    }

    @Test
    fun `a wallet cancellation in same-device still gets the redirect back`() {
        val request = PresentationRequest.forVct(CedSim.VCT, CedSim.CLAIM_PATHS, CedSim.CREDENTIAL_QUERY_ID)
        val started = flow.start(request, FlowMode.SAME_DEVICE)
        val handled =
            flow.handleWalletResponse(
                started.id,
                DirectPostBody(mapOf("error" to "access_denied")),
            )
        assertThat(handled.outcome).isInstanceOf(FlowOutcome.WalletErrorAcknowledged::class.java)
        // RPR-59: the user who cancelled in the wallet must still land back on the RP.
        assertThat(handled.redirectUri).contains("response_code=")
    }

    private fun lastTransactionId(): dev.zilath.verifier.openid4vp.TransactionId {
        // presentSimulatedCed does not expose the id: recover it from the request JWT
        // it minted (state == transaction id in this profile).
        return checkNotNull(lastStartedId) { "no transaction started" }
    }

    @Test
    fun `keys survive a write-read roundtrip`(
        @TempDir dir: Path,
    ) {
        CedSim.writeKeys(dir, keys)
        val reloaded = CedSim.readKeys(dir)
        assertThat(reloaded.anchor.toJSONString()).isEqualTo(keys.anchor.toJSONString())
        assertThat(reloaded.issuerCredential.keyID).isEqualTo(keys.issuerCredential.keyID)
        assertThat(dir.resolve("anchor-jwks.json")).exists()
    }
}
