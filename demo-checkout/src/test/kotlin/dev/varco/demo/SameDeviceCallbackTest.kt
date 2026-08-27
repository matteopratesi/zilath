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
package dev.varco.demo

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import dev.varco.verifier.core.CredentialStatus
import dev.varco.verifier.core.StatusChecker
import dev.varco.verifier.core.TrustDecision
import dev.varco.verifier.core.TrustEvaluator
import dev.varco.verifier.openid4vp.DirectPostBody
import dev.varco.verifier.openid4vp.FlowMode
import dev.varco.verifier.openid4vp.FlowOutcome
import dev.varco.verifier.openid4vp.PresentationRequest
import dev.varco.verifier.openid4vp.RelyingPartyConfiguration
import dev.varco.verifier.openid4vp.RpEndpoints
import dev.varco.verifier.openid4vp.RpKeys
import dev.varco.verifier.openid4vp.StartedTransaction
import dev.varco.verifier.openid4vp.TransactionId
import dev.varco.verifier.openid4vp.VerificationFlow
import dev.varco.verifier.openid4vp.VerificationReceipts
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Clock

/** The return-leg redirect must point at the REAL ticket URL (regression: a broken
 *  string interpolation once produced the literal `${'$'}{txId.value}` here). */
class SameDeviceCallbackTest {
    private val config =
        RelyingPartyConfiguration(
            clientId = "https://demo.varco.example",
            endpoints = RpEndpoints("https://demo.varco.example/req", "https://demo.varco.example/res"),
            keys =
                RpKeys(
                    requestSigningKey = ECKeyGenerator(Curve.P_256).keyID("t-sign").generate(),
                    responseEncryptionKey = ECKeyGenerator(Curve.P_256).keyID("t-enc").generate(),
                ),
            trustEvaluator = TrustEvaluator { TrustDecision.Untrusted("test") },
            statusChecker = StatusChecker { CredentialStatus.VALID },
        )

    private fun controllerWith(flow: VerificationFlow) =
        DemoCheckoutController(
            flow = flow,
            receipts = VerificationReceipts(config, Clock.systemUTC()),
            clock = Clock.systemUTC(),
            pidVct = "urn:eudi:pid:it:1",
            credentialMode = "pid",
        )

    private fun flowStub(consumed: TransactionId?) =
        object : VerificationFlow {
            override fun start(
                request: PresentationRequest,
                mode: FlowMode,
            ): StartedTransaction = error("not used")

            override fun requestJwtFor(txId: TransactionId): String? = null

            override fun handleWalletResponse(
                txId: TransactionId,
                body: DirectPostBody,
            ): FlowOutcome = FlowOutcome.Unknown

            override fun awaitOutcome(txId: TransactionId): FlowOutcome = FlowOutcome.Unknown

            override fun sameDeviceRedirectFor(txId: TransactionId): String? = null

            override fun consumeResponseCode(code: String): TransactionId? = consumed
        }

    @Test
    fun `a valid response code redirects to the ticket of its transaction`() {
        val response = controllerWith(flowStub(TransactionId("tx-42"))).sameDeviceCallback("code")
        assertThat(response.statusCode.value()).isEqualTo(302)
        assertThat(response.headers.location.toString()).isEqualTo("/demo/ticket/tx-42")
    }

    @Test
    fun `an unknown or replayed response code lands on the not-found page`() {
        val response = controllerWith(flowStub(null)).sameDeviceCallback("nope")
        assertThat(response.statusCode.value()).isEqualTo(404)
    }
}
