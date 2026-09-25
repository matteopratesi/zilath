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

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/** The same-device return leg: who gets the response code, and when the outcome becomes readable. */
class SameDeviceFlowTest : FlowTestSupport() {
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
}
