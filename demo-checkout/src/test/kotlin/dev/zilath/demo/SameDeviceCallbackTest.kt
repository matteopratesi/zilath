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
import org.springframework.http.HttpHeaders
import org.springframework.mock.web.MockHttpServletRequest
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

    /** A controller that started the known transaction, and the session secret it set for it. */
    private class Started(
        val controller: DemoCheckoutController,
        val session: String,
    )

    private fun controllerFor(flow: VerificationFlow): DemoCheckoutController {
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
        return DemoCheckoutController(
            flow = flow,
            receipts = VerificationReceipts(config, Clock.systemUTC()),
            clock = Clock.systemUTC(),
            pidVct = "urn:eudi:pid:it:1",
            credentialMode = "pid",
        )
    }

    /** The known session exists because this controller started it, in this browser. */
    private fun startedWith(flow: VerificationFlow): Started {
        val controller = controllerFor(flow)
        val response = controller.startEntitledPurchase("same-device", null, MockHttpServletRequest())
        return Started(controller, sessionOf(response.headers.getFirst(HttpHeaders.SET_COOKIE)))
    }

    private fun sessionOf(setCookie: String?): String =
        checkNotNull(setCookie).substringAfter("${DemoCheckoutController.SESSION_COOKIE}=").substringBefore(';')

    @Test
    fun `a valid code on its own transaction redirects to the ticket`() {
        val flow = RecordingFlow(known, consumes = true)
        val started = startedWith(flow)
        val response = started.controller.sameDeviceCallback(known.value, "a-code", null, started.session)
        assertThat(response.statusCode.value()).isEqualTo(302)
        assertThat(response.headers.location.toString()).isEqualTo("/demo/ticket/tx-known")
    }

    @Test
    fun `a browser that did not start the transaction cannot complete its return`() {
        // Session fixation: whoever started the transaction sends its link to someone else,
        // whose wallet answers and whose browser comes back here. It holds no session of this
        // transaction, and the code must stay unspent.
        val flow = RecordingFlow(known, consumes = true)
        val started = startedWith(flow)
        for (session in listOf(null, "another-browser-session")) {
            assertThat(
                started.controller
                    .sameDeviceCallback(known.value, "a-code", null, session)
                    .statusCode
                    .value(),
            ).describedAs("session %s", session)
                .isEqualTo(401)
        }
        assertThat(flow.consumeCalls).isZero()
        assertThat(
            started.controller
                .sameDeviceCallback(known.value, "a-code", null, started.session)
                .statusCode
                .value(),
        ).isEqualTo(302)
    }

    @Test
    fun `the session cookie is HttpOnly, Lax, scoped to the demo, and Secure off the loopback`() {
        val controller = controllerFor(RecordingFlow(known, consumes = true))
        val local =
            checkNotNull(
                controller
                    .startEntitledPurchase("cross-device", null, MockHttpServletRequest())
                    .headers
                    .getFirst(HttpHeaders.SET_COOKIE),
            )
        assertThat(local).contains("HttpOnly", "SameSite=Lax", "Path=/demo").doesNotContain("Secure")
        val deployed =
            checkNotNull(
                controller
                    .startEntitledPurchase(
                        "cross-device",
                        null,
                        MockHttpServletRequest().apply {
                            serverName =
                                "demo.example"
                        },
                    ).headers
                    .getFirst(HttpHeaders.SET_COOKIE),
            )
        assertThat(deployed).contains("Secure", "HttpOnly")
        // A second purchase in the same browser keeps its session, and so the first one.
        val session = sessionOf(local)
        val again = controller.startEntitledPurchase("cross-device", session, MockHttpServletRequest())
        assertThat(sessionOf(again.headers.getFirst(HttpHeaders.SET_COOKIE))).isEqualTo(session)
    }

    @Test
    fun `an error in the query is a bad request and never spends the code`() {
        val flow = RecordingFlow(known, consumes = true)
        val started = startedWith(flow)
        val response = started.controller.sameDeviceCallback(known.value, "a-code", "server_error", started.session)
        assertThat(response.statusCode.value()).isEqualTo(400)
        assertThat(flow.consumeCalls).isZero()
    }

    @Test
    fun `a session neither the demo nor the flow knows is unauthorized`() {
        // The flow is asked, and redeems nothing: a code only ever redeems its own transaction.
        val flow = RecordingFlow(known, consumes = true)
        val response = startedWith(flow).controller.sameDeviceCallback("someone-elses-tx", "a-code", null, null)
        assertThat(response.statusCode.value()).isEqualTo(401)
    }

    @Test
    fun `a return to a transaction the demo did not start hands the reader to the user-agent`() {
        // A conformance run: started outside these pages, which never point at it. The token
        // the flow issued for the return goes to the one that came back, and is not kept
        // anywhere an id alone reaches.
        val conformance = TransactionId("tx-conformance")
        val flow = RecordingFlow(known, consumes = true, redeemable = setOf(known, conformance))
        val response = startedWith(flow).controller.sameDeviceCallback(conformance.value, "a-code", null, null)
        assertThat(response.statusCode.value()).isEqualTo(200)
        assertThat(response.headers.location).isNull()
        assertThat(response.headers.cacheControl).isEqualTo("no-store")
        assertThat(response.body).isEqualTo("""{"status":"returned","pollToken":"reader"}""")
    }

    @Test
    fun `a missing code is unauthorized`() {
        val flow = RecordingFlow(known, consumes = true)
        val started = startedWith(flow)
        assertThat(
            started.controller
                .sameDeviceCallback(known.value, null, null, started.session)
                .statusCode
                .value(),
        ).isEqualTo(401)
        assertThat(
            started.controller
                .sameDeviceCallback(known.value, "  ", null, started.session)
                .statusCode
                .value(),
        ).isEqualTo(401)
    }

    @Test
    fun `a code the flow refuses is a bad request`() {
        val flow = RecordingFlow(known, consumes = false)
        val started = startedWith(flow)
        val response = started.controller.sameDeviceCallback(known.value, "stale", null, started.session)
        assertThat(response.statusCode.value()).isEqualTo(400)
        assertThat(response.body).contains("invalid_response_code")
    }
}
