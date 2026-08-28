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
    ) : VerificationFlow {
        var consumeCalls = 0
            private set

        override fun start(
            request: PresentationRequest,
            mode: FlowMode,
        ): StartedTransaction = error("not used")

        override fun requestJwtFor(txId: TransactionId): String? = null

        override fun handleWalletResponse(
            txId: TransactionId,
            body: DirectPostBody,
        ): FlowOutcome = FlowOutcome.Unknown

        override fun awaitOutcome(txId: TransactionId): FlowOutcome =
            if (txId == knownId) FlowOutcome.Pending else FlowOutcome.Unknown

        override fun sameDeviceRedirectFor(txId: TransactionId): String? = null

        override fun consumeResponseCode(
            txId: TransactionId,
            code: String,
        ): Boolean {
            consumeCalls++
            return consumes && txId == knownId
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
                statusChecker = StatusChecker { CredentialStatus.VALID },
            )
        return DemoCheckoutController(
            flow = flow,
            receipts = VerificationReceipts(config, Clock.systemUTC()),
            clock = Clock.systemUTC(),
            pidVct = "urn:eudi:pid:it:1",
            credentialMode = "pid",
        )
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
    fun `an unknown session is unauthorized, and the code is left alone`() {
        val flow = RecordingFlow(known, consumes = true)
        val response = controllerWith(flow).sameDeviceCallback("someone-elses-tx", "a-code", null)
        assertThat(response.statusCode.value()).isEqualTo(401)
        assertThat(flow.consumeCalls).isZero()
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
