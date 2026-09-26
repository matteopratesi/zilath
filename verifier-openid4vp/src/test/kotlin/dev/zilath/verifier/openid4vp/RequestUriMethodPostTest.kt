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

import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.junit.jupiter.api.Test

/**
 * `request_uri_method=post` (OpenID4VP 1.0 §5.10): a wallet may ask for the request object
 * with POST and a `wallet_nonce`, which the object must then carry. Before the fourth
 * internal review only GET existed, which a wallet must fall back to, but a wallet that
 * wanted its own nonce in the object had no way to get it.
 */
class RequestUriMethodPostTest : FlowTestSupport() {
    @Test
    fun `a request object asked for with a wallet nonce carries it, and only that one`() {
        val started = startForPid()
        val withNonce = SignedJWT.parse(flow.requestJwtFor(started.id, "wallet-nonce-1")).jwtClaimsSet
        assertThat(withNonce.getStringClaim("wallet_nonce")).isEqualTo("wallet-nonce-1")
        // Nothing of it is kept: the next object, asked for without one, carries none.
        val without = SignedJWT.parse(flow.requestJwtFor(started.id)).jwtClaimsSet
        assertThat(without.claims).doesNotContainKey("wallet_nonce")
        assertThat(SignedJWT.parse(flow.requestJwtFor(started.id, null)).jwtClaimsSet.claims)
            .doesNotContainKey("wallet_nonce")
    }

    @Test
    fun `a wallet nonce longer than the bound is refused`() {
        val started = startForPid()
        assertThat(flow.requestJwtFor(started.id, "n".repeat(VerificationFlow.MAX_WALLET_NONCE_LENGTH))).isNotNull()
        assertThatIllegalArgumentException()
            .isThrownBy { flow.requestJwtFor(started.id, "n".repeat(VerificationFlow.MAX_WALLET_NONCE_LENGTH + 1)) }
    }

    @Test
    fun `the QR payload announces the POST leg only where there is one`() {
        assertThat(startForPid().qrPayload).doesNotContain("request_uri_method")

        val posting = config.copy(endpoints = config.endpoints.copy(requestUriMethodPost = true))
        OpenId4VpVerificationFlow.withInMemoryStore(posting, SdJwtVcCredentialVerifier(), clock).use {
            val started = it.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
            assertThat(started.qrPayload).endsWith("&request_uri_method=post")
            val sameDevice =
                it.start(
                    PresentationRequest.forTestPid("urn:zilath:test:entitlement"),
                    FlowMode.SAME_DEVICE,
                )
            assertThat(sameDevice.qrPayload).endsWith("&request_uri_method=post")
        }
    }

    @Test
    fun `a flow that cannot carry a wallet nonce serves no object for one`() {
        // The interface's default, for implementations written before the POST leg existed.
        val legacy =
            object : VerificationFlow by flow {
                override fun requestJwtFor(txId: TransactionId): String? = flow.requestJwtFor(txId)

                override fun requestJwtFor(
                    txId: TransactionId,
                    walletNonce: String?,
                ): String? = super.requestJwtFor(txId, walletNonce)
            }
        val started = startForPid()
        assertThat(legacy.requestJwtFor(started.id, null)).isNotNull()
        assertThat(legacy.requestJwtFor(started.id, "wallet-nonce-1")).isNull()
    }
}
