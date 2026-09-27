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

import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * Who may read an outcome. The transaction id is in the QR code and the links a user is
 * sent: before the fourth internal review it was also the only thing awaitOutcome asked
 * for, and whoever photographed the checkout's screen read the verified claims.
 */
class OutcomeReadTest : FlowTestSupport() {
    @Test
    fun `the transaction id shown in the QR reads nothing`() {
        val started = startForPid()
        val requestUri = URLDecoder.decode(started.qrPayload.substringAfter("request_uri="), StandardCharsets.UTF_8)
        val fromQr = TransactionId(requestUri.substringAfterLast('/'))
        assertThat(fromQr).isEqualTo(started.id)
        flow.handleWalletResponse(started.id, walletBody(started))

        // Whatever a bystander can build from the screen answers Unknown, exactly as an id
        // that does not exist: no claims, and no oracle for which transactions are real.
        for (guess in listOf(PollToken(fromQr.value), PollToken(requestUri), PollToken(""))) {
            assertThat(flow.awaitOutcome(fromQr, guess)).isEqualTo(FlowOutcome.Unknown)
        }
        assertThat(flow.awaitOutcome(TransactionId("ghost"), started.pollToken)).isEqualTo(FlowOutcome.Unknown)
        // The checkout that started the transaction reads it.
        assertThat(flow.awaitOutcome(fromQr, started.pollToken)).isInstanceOf(FlowOutcome.Verified::class.java)
    }

    @Test
    fun `the poll token travels nowhere a wallet or a bystander sees it`() {
        val started = flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val token = started.pollToken.value
        assertThat(Base64URL(token).decode()).hasSize(32)
        val jar = SignedJWT.parse(checkNotNull(flow.requestJwtFor(started.id)))
        val handled = flow.handleWalletResponse(started.id, walletBody(started))
        val seen =
            listOf(
                started.qrPayload,
                started.requestUri,
                started.id.value,
                jar.header.toString(),
                jar.payload.toString(),
                checkNotNull(handled.redirectUri),
                started.toString(),
                started.pollToken.toString(),
            )
        assertThat(seen).allSatisfy { assertThat(it).doesNotContain(token) }
    }

    @Test
    fun `same-device, only the user-agent that comes back with the code reads the outcome`() {
        // Session fixation (OpenID4VP §14.2): whoever STARTS a same-device transaction can
        // send its link to someone else, whose wallet then answers. The starter's token must
        // never read that person's outcome; the browser the wallet returns to must.
        val started = flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val handled = flow.handleWalletResponse(started.id, walletBody(started))
        assertThat(handled.outcome).isInstanceOf(FlowOutcome.Verified::class.java)
        assertThat(flow.awaitOutcome(started.id, started.pollToken)).isEqualTo(FlowOutcome.Pending)

        val code = checkNotNull(handled.redirectUri).substringAfter("response_code=")
        val reader = checkNotNull(flow.consumeResponseCode(started.id, code))
        assertThat(reader).isNotEqualTo(started.pollToken)
        assertThat(flow.awaitOutcome(started.id, started.pollToken)).isEqualTo(FlowOutcome.Unknown)
        assertThat(flow.awaitOutcome(started.id, reader)).isInstanceOf(FlowOutcome.Verified::class.java)
    }

    @Test
    fun `the store keeps the hash of the poll token, never the token`() {
        val retaining = RetainingTransactionStore()
        val retainingFlow = OpenId4VpVerificationFlow(config, SdJwtVcCredentialVerifier(), retaining, clock)
        val started = retainingFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        val stored = checkNotNull(retaining.get(started.id))
        assertThat(stored.pollTokenHash).isNotEqualTo(started.pollToken.value)
        assertThat(stored.toString()).doesNotContain(started.pollToken.value)
        assertThat(retainingFlow.awaitOutcome(started.id, started.pollToken)).isEqualTo(FlowOutcome.Pending)
    }
}
