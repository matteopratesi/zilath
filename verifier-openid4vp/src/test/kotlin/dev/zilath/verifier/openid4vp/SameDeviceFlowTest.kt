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

import dev.zilath.verifier.core.RejectionReason
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
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
        assertThat(verified.outcome).isInstanceOf(FlowOutcome.Verified::class.java)

        val attacker = flow.handleWalletResponse(started.id, DirectPostBody(mapOf("error" to "access_denied")))
        assertThat(attacker.outcome).isInstanceOf(FlowOutcome.WalletErrorAcknowledged::class.java)

        // The attacker is owed an acknowledgement, and nothing else.
        assertThat(attacker.redirectUri).isNull()

        // The verification itself is untouched: the wallet's own ack carries the ticket,
        // and the user completes the flow they started.
        val code = checkNotNull(verified.redirectUri).substringAfter("response_code=")
        assertThat(verified.redirectUri).isEqualTo("https://rp.example/cb/${started.id.value}?response_code=$code")
        assertThat(flow.consumeResponseCode(started.id, code)).isNotNull()
    }

    @Test
    fun `a wallet error while the transaction is still open still returns the user`() {
        // The legitimate case the fix must not break (RPR-59): the user cancels inside the
        // wallet, the wallet posts an error, and the acknowledgement must still bring them
        // back to the relying party rather than stranding them.
        val started = flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val cancelled = flow.handleWalletResponse(started.id, DirectPostBody(mapOf("error" to "access_denied")))
        assertThat(cancelled.redirectUri).contains("response_code=")
    }

    @Test
    fun `a rejected same-device presentation gets no return ticket, and reads as never returned`() {
        // A code used to be minted for every recorded outcome, rejections included, while the
        // endpoint answers a rejection with an error that carries no redirect: a live bearer
        // secret in the store that nobody could use.
        val retaining = RetainingTransactionStore()
        val retainingFlow = OpenId4VpVerificationFlow(config, SdJwtVcCredentialVerifier(), retaining, clock)
        val started =
            retainingFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val rejected =
            retainingFlow.handleWalletResponse(
                started.id,
                walletBody(started, nonceOverride = "stolen", source = retainingFlow),
            )
        assertThat((rejected.outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.NONCE_MISMATCH)
        assertThat(rejected.redirectUri).isNull()
        assertThat(retaining.get(started.id)?.responseCode).isNull()
        // What the page that started it reads: pending, then expired — never the rejection.
        assertThat(retainingFlow.awaitOutcome(started.id, started.pollToken)).isEqualTo(FlowOutcome.Pending)
        clock.advance(config.transactionTimeToLive.plusSeconds(1))
        assertThat(retainingFlow.awaitOutcome(started.id, started.pollToken)).isEqualTo(FlowOutcome.Expired)
    }

    @Test
    fun `only the call that recorded the outcome gets the return ticket, however it is guessed`() {
        // The ticket used to go to whoever presented an outcome EQUAL to the recorded one.
        // After a genuine cancellation, a second POST with the same `error` — access_denied
        // is the only one a cancelling wallet sends — got the same response code, and could
        // burn it on the callback before the user's own browser arrived.
        val started = flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val wallet = flow.handleWalletResponse(started.id, DirectPostBody(mapOf("error" to "access_denied")))
        val guessed = flow.handleWalletResponse(started.id, DirectPostBody(mapOf("error" to "access_denied")))
        val other = flow.handleWalletResponse(started.id, DirectPostBody(mapOf("error" to "server_error")))
        assertThat(guessed.outcome).isEqualTo(wallet.outcome)
        assertThat(wallet.redirectUri).contains("response_code=")
        assertThat(guessed.redirectUri).isNull()
        assertThat(other.redirectUri).isNull()
        assertThat(flow.consumeResponseCode(started.id, wallet.redirectUri!!.substringAfter("response_code=")))
            .isNotNull()
    }

    @Test
    fun `the return ticket does not depend on the store keeping the outcome bit for bit`() {
        // The ticket was released only while the stored outcome EQUALLED the one the caller
        // presented: a store that minimised what it kept — a shortened wallet description, a
        // dropped detail — stranded the user who had cancelled in the wallet.
        val minimising = MinimisingTransactionStore()
        val minimisingFlow = OpenId4VpVerificationFlow(config, SdJwtVcCredentialVerifier(), minimising, clock)
        val started =
            minimisingFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val cancelled =
            minimisingFlow.handleWalletResponse(
                started.id,
                DirectPostBody(mapOf("error" to "access_denied", "error_description" to "the holder declined")),
            )
        assertThat(minimising.get(started.id)?.outcome).isNotEqualTo(cancelled.outcome)
        assertThat(cancelled.redirectUri).contains("response_code=")
    }

    @Test
    fun `the acknowledgement reads nothing back from a store that reads from a replica`() {
        // The ack wrote through compareAndUpdate and read back through get in the same
        // request: a store whose get is served by a replica that has not caught up — the
        // default read of several shared stores — left every same-device holder without a
        // redirect, verified or cancelled.
        val stale = StaleReplicaTransactionStore()
        val staleFlow = OpenId4VpVerificationFlow(config, SdJwtVcCredentialVerifier(), stale, clock)

        val verifying =
            staleFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val body = walletBody(verifying, source = staleFlow)
        val verified = staleFlow.handleWalletResponse(verifying.id, body)
        assertThat(verified.outcome).isInstanceOf(FlowOutcome.Verified::class.java)
        assertThat(verified.redirectUri).contains("response_code=")

        val cancelling =
            staleFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val cancelled = staleFlow.handleWalletResponse(cancelling.id, DirectPostBody(mapOf("error" to "access_denied")))
        assertThat(cancelled.redirectUri).contains("response_code=")
    }

    @Test
    fun `a response code counts as consumed only if the store committed it`() {
        // The decision came from a variable the update function set. A store may run that
        // function and not commit its result — an optimistic store whose entry is removed
        // between its read and its write returns null — and the flow then reported a
        // consumption that never happened.
        val interleaving = RemovedDuringUpdateStore(RetainingTransactionStore())
        val interleavedFlow = OpenId4VpVerificationFlow(config, SdJwtVcCredentialVerifier(), interleaving, clock)
        val started =
            interleavedFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val handled = interleavedFlow.handleWalletResponse(started.id, walletBody(started, source = interleavedFlow))
        val code = checkNotNull(handled.redirectUri).substringAfter("response_code=")
        interleaving.removeDuringNextUpdate = true
        assertThat(interleavedFlow.consumeResponseCode(started.id, code)).isNull()
        assertThat(interleaving.updatesRun).isPositive()
    }

    @Test
    fun `a response code is consumed exactly once under contention`() {
        val optimistic = OptimisticTransactionStore()
        val optimisticFlow = OpenId4VpVerificationFlow(config, SdJwtVcCredentialVerifier(), optimistic, clock)
        val started =
            optimisticFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val handled = optimisticFlow.handleWalletResponse(started.id, walletBody(started, source = optimisticFlow))
        val code = checkNotNull(handled.redirectUri).substringAfter("response_code=")
        val pool =
            java.util.concurrent.Executors
                .newFixedThreadPool(CONTENDERS)
        try {
            val gate = java.util.concurrent.CountDownLatch(1)
            val results =
                (1..CONTENDERS).map {
                    pool.submit<Boolean> {
                        gate.await()
                        optimisticFlow.consumeResponseCode(started.id, code) != null
                    }
                }
            gate.countDown()
            assertThat(results.count { it.get() }).isEqualTo(1)
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun `a transaction prints neither its secrets nor the person`() {
        // A data class prints every property: the nonce and the response code — bearer
        // secrets for the whole time to live — and, once verified, the disclosed claims.
        val retaining = RetainingTransactionStore()
        val retainingFlow = OpenId4VpVerificationFlow(config, SdJwtVcCredentialVerifier(), retaining, clock)
        val started =
            retainingFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val handled = retainingFlow.handleWalletResponse(started.id, walletBody(started, source = retainingFlow))
        val verified = handled.outcome
        val stored = checkNotNull(retaining.get(started.id))
        assertThat(stored.responseCode).isNotNull()
        assertThat(stored.outcome).isInstanceOf(FlowOutcome.Verified::class.java)

        val printed = stored.toString()
        assertThat(printed)
            .contains(started.id.value, "VERIFIED", "Verified")
            .doesNotContain(stored.nonce, stored.responseCode, "Ada", "Lovelace")
        // The outcome on its own names the claims and nothing more.
        assertThat(verified.toString()).contains("given_name").doesNotContain("Ada", "Lovelace", "true")
        assertThat(handled.toString()).doesNotContain(stored.responseCode, "Ada")
    }

    private companion object {
        const val CONTENDERS = 32
    }
}
