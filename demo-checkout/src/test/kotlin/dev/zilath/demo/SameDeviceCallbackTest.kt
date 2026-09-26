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
package dev.zilath.demo

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import dev.zilath.verifier.core.CredentialStatus
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.TrustEvaluator
import dev.zilath.verifier.openid4vp.DirectPostBody
import dev.zilath.verifier.openid4vp.FlowMode
import dev.zilath.verifier.openid4vp.FlowOutcome
import dev.zilath.verifier.openid4vp.HandledResponse
import dev.zilath.verifier.openid4vp.PollToken
import dev.zilath.verifier.openid4vp.PresentationRequest
import dev.zilath.verifier.openid4vp.RelyingPartyConfiguration
import dev.zilath.verifier.openid4vp.RpEndpoints
import dev.zilath.verifier.openid4vp.RpKeys
import dev.zilath.verifier.openid4vp.StartedTransaction
import dev.zilath.verifier.openid4vp.TransactionId
import dev.zilath.verifier.openid4vp.VerificationFlow
import dev.zilath.verifier.openid4vp.VerificationReceipts
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Clock

/**
 * The same-device return leg: an unknown session, a missing code and an error carried in
 * the query must be told apart — and an error must never spend the code, which is what a
 * stub flow can prove and an end-to-end call cannot.
 */
class SameDeviceCallbackTest {
    private val known = TransactionId("tx-known")

    /** Records what the controller asks of the flow. */
    private class RecordingFlow(
        private val knownId: TransactionId,
        private val consumes: Boolean,
        /** The transactions whose code this flow redeems; the demo started only [knownId]. */
        private val redeemable: Set<TransactionId> = setOf(knownId),
    ) : VerificationFlow {
        var consumeCalls = 0
            private set

        override fun start(
            request: PresentationRequest,
            mode: FlowMode,
        ): StartedTransaction = StartedTransaction(knownId, "https://rp/req", "openid4vp://x", PollToken("poll"))

        override fun requestJwtFor(txId: TransactionId): String? = null

        override fun handleWalletResponse(
            txId: TransactionId,
            body: DirectPostBody,
        ): HandledResponse = HandledResponse(FlowOutcome.Unknown)

        override fun awaitOutcome(
            txId: TransactionId,
            pollToken: PollToken,
        ): FlowOutcome = if (txId == knownId) FlowOutcome.Pending else FlowOutcome.Unknown

        override fun consumeResponseCode(
            txId: TransactionId,
            code: String,
        ): PollToken? {
            consumeCalls++
            return PollToken("reader").takeIf { consumes && txId in redeemable }
        }
    }

    private fun controllerWith(flow: VerificationFlow): DemoCheckoutController {
        val config =
            RelyingPartyConfiguration(
                clientId = "https://demo.zilath.example",
                endpoints = RpEndpoints("https://demo.zilath.example/req", "https://demo.zilath.example/res"),
                keys =
                    RpKeys(
                        requestSigningKey = ECKeyGenerator(Curve.P_256).keyID("t-sign").generate(),
                        responseEncryptionKey = ECKeyGenerator(Curve.P_256).keyID("t-enc").generate(),
                    ),
                trustEvaluator = TrustEvaluator { TrustDecision.Untrusted("test") },
                statusChecker = StatusChecker { _, _ -> CredentialStatus.VALID },
            )
        val controller =
            DemoCheckoutController(
                flow = flow,
                receipts = VerificationReceipts(config, Clock.systemUTC()),
                clock = Clock.systemUTC(),
                pidVct = "urn:eudi:pid:it:1",
                credentialMode = "pid",
            )
        // The known session exists because this controller started it.
        controller.startEntitledPurchase("same-device")
        return controller
    }

    @Test
    fun `a valid code on its own transaction redirects to the ticket`() {
        val flow = RecordingFlow(known, consumes = true)
        val response = controllerWith(flow).sameDeviceCallback(known.value, "a-code", null)
        assertThat(response.statusCode.value()).isEqualTo(302)
        assertThat(response.headers.location.toString()).isEqualTo("/demo/ticket/tx-known")
    }

    @Test
    fun `an error in the query is a bad request and never spends the code`() {
        val flow = RecordingFlow(known, consumes = true)
        val response = controllerWith(flow).sameDeviceCallback(known.value, "a-code", "server_error")
        assertThat(response.statusCode.value()).isEqualTo(400)
        assertThat(flow.consumeCalls).isZero()
    }

    @Test
    fun `a session neither the demo nor the flow knows is unauthorized`() {
        // The flow is asked, and redeems nothing: a code only ever redeems its own transaction.
        val flow = RecordingFlow(known, consumes = true)
        val response = controllerWith(flow).sameDeviceCallback("someone-elses-tx", "a-code", null)
        assertThat(response.statusCode.value()).isEqualTo(401)
    }

    @Test
    fun `a return to a transaction the demo did not start hands the reader to the user-agent`() {
        // A conformance run: started outside these pages, which read by id alone and so are
        // never pointed at it. The token the flow issued for the return goes to the one that
        // came back, and is not kept anywhere an id alone reaches.
        val conformance = TransactionId("tx-conformance")
        val flow = RecordingFlow(known, consumes = true, redeemable = setOf(known, conformance))
        val response = controllerWith(flow).sameDeviceCallback(conformance.value, "a-code", null)
        assertThat(response.statusCode.value()).isEqualTo(200)
        assertThat(response.headers.location).isNull()
        assertThat(response.headers.cacheControl).isEqualTo("no-store")
        assertThat(response.body).isEqualTo("""{"status":"returned","pollToken":"reader"}""")
    }

    @Test
    fun `a missing code is unauthorized`() {
        val flow = RecordingFlow(known, consumes = true)
        assertThat(controllerWith(flow).sameDeviceCallback(known.value, null, null).statusCode.value())
            .isEqualTo(401)
        assertThat(controllerWith(flow).sameDeviceCallback(known.value, "  ", null).statusCode.value())
            .isEqualTo(401)
    }

    @Test
    fun `a code the flow refuses is a bad request`() {
        val flow = RecordingFlow(known, consumes = false)
        val response = controllerWith(flow).sameDeviceCallback(known.value, "stale", null)
        assertThat(response.statusCode.value()).isEqualTo(400)
        assertThat(response.body).contains("invalid_response_code")
    }
}
