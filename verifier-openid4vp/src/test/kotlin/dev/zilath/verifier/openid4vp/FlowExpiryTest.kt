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
import dev.zilath.verifier.core.RejectionReason
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import dev.zilath.verifier.core.TestVectors
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.time.Duration

/** Expiry is the flow's: nothing of a transaction is handed out, or kept readable, past its time to live. */
class FlowExpiryTest : FlowTestSupport() {
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
    fun `an expired wallet error does not keep the wallet's own text readable`() {
        // The tombstone drops the description too: it came from the wallet response and
        // has no business outliving the transaction it belonged to.
        // Cross-device on purpose: a same-device transaction with no completed return leg
        // answers Expired whatever the tombstone did, so that version of this test would
        // have passed with the redaction removed — it would have tested nothing.
        val started = startForPid()
        flow.handleWalletResponse(
            started.id,
            DirectPostBody(mapOf("error" to "access_denied", "error_description" to "user said no")),
        )
        clock.advance(Duration.ofMinutes(6))
        val outcome = flow.awaitOutcome(started.id)
        assertThat(outcome).isInstanceOf(FlowOutcome.WalletErrorAcknowledged::class.java)
        assertThat((outcome as FlowOutcome.WalletErrorAcknowledged).description).isNull()
        assertThat(outcome.error).isEqualTo("access_denied")
    }

    @Test
    fun `a time to live beyond the cap is refused at construction, and the cap itself works`() {
        // Long.MAX_VALUE seconds used to pass construction and overflow in createdAt + ttl
        // at the first request object: a configuration error found by the first wallet.
        assertThatThrownBy { config.copy(transactionTimeToLive = Duration.ofSeconds(Long.MAX_VALUE)) }
            .isInstanceOf(IllegalArgumentException::class.java)
        assertThatThrownBy {
            config.copy(transactionTimeToLive = RelyingPartyConfiguration.MAX_TIME_TO_LIVE.plusSeconds(1))
        }.isInstanceOf(IllegalArgumentException::class.java)
        val atCap = config.copy(transactionTimeToLive = RelyingPartyConfiguration.MAX_TIME_TO_LIVE)
        val atCapFlow = OpenId4VpVerificationFlow.withInMemoryStore(atCap, SdJwtVcCredentialVerifier(), clock)
        val first = atCapFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        val jar = SignedJWT.parse(checkNotNull(atCapFlow.requestJwtFor(first.id)))
        assertThat(jar.jwtClaimsSet.expirationTime.toInstant())
            .isEqualTo(TestVectors.NOW.plus(RelyingPartyConfiguration.MAX_TIME_TO_LIVE))
        atCapFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
    }

    @Test
    fun `an expired transaction cannot complete`() {
        val started = startForPid()
        val body = walletBody(started)
        clock.advance(Duration.ofMinutes(6))
        // Expired on every path, and consistently: the entry is redacted in place and kept
        // until the store drops it, so later reads still say "expired", never "unknown" —
        // and never carry anything the transaction held.
        assertThat(flow.awaitOutcome(started.id)).isEqualTo(FlowOutcome.Expired)
        assertThat(flow.handleWalletResponse(started.id, body)).isEqualTo(FlowOutcome.Expired)
        assertThat(flow.awaitOutcome(started.id)).isEqualTo(FlowOutcome.Expired)
        assertThat(flow.requestJwtFor(started.id)).isNull()
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
        // the first read after expiry took the entry, so what is left is Unknown.
        assertThat(flow.awaitOutcome(started.id)).isIn(FlowOutcome.Expired, FlowOutcome.Unknown)
        assertThat(flow.consumeResponseCode(started.id, code)).isFalse()
        assertThat(flow.awaitOutcome(started.id)).isIn(FlowOutcome.Expired, FlowOutcome.Unknown)
    }

    @Test
    fun `a verified outcome is never read past the time to live, whatever the store keeps`() {
        // awaitOutcome returned a recorded outcome before looking at the clock, and left the
        // redaction to the store: one that kept entries longer — a TTL of its own, a
        // periodic cleanup — kept the claims readable for as long as it kept the entry.
        val retaining = RetainingTransactionStore()
        val retainingFlow = OpenId4VpVerificationFlow(config, SdJwtVcCredentialVerifier(), retaining, clock)

        val crossDevice = retainingFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        retainingFlow.handleWalletResponse(crossDevice.id, walletBody(crossDevice, source = retainingFlow))

        val sameDevice =
            retainingFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val verified = retainingFlow.handleWalletResponse(sameDevice.id, walletBody(sameDevice, source = retainingFlow))
        val code =
            checkNotNull(retainingFlow.sameDeviceRedirectFor(sameDevice.id, verified)).substringAfter("response_code=")
        assertThat(retainingFlow.consumeResponseCode(sameDevice.id, code)).isTrue()
        assertThat(retainingFlow.awaitOutcome(sameDevice.id)).isInstanceOf(FlowOutcome.Verified::class.java)

        clock.advance(config.transactionTimeToLive.plusSeconds(1))
        for (id in listOf(crossDevice.id, sameDevice.id)) {
            val late = retainingFlow.awaitOutcome(id)
            assertThat(late).isEqualTo(FlowOutcome.Rejected(RejectionReason.EXPIRED))
            // ...and redacted where it is kept, not only in the answer.
            assertThat(retaining.get(id)?.outcome).isEqualTo(FlowOutcome.Rejected(RejectionReason.EXPIRED))
            assertThat(retaining.get(id)?.responseCode).isNull()
            assertThat(retainingFlow.awaitOutcome(id)).isEqualTo(late)
        }
    }

    @Test
    fun `a response to an expired transaction leaves it expired, error or presentation`() {
        // An error posted to an expired but not yet swept transaction used to become its
        // outcome, while a valid presentation next to it was answered Expired and removed:
        // the checkout read "wallet error" for one and "unknown" for the other.
        val erred = startForPid()
        val presented = startForPid()
        val presentation = walletBody(presented)
        clock.advance(config.transactionTimeToLive.plusSeconds(1))
        val ack =
            flow.handleWalletResponse(
                erred.id,
                DirectPostBody(mapOf("error" to "access_denied", "error_description" to "too late")),
            )
        // Still acknowledged to the wallet: OpenID4VP §8.2 owes the error an answer.
        assertThat(ack).isEqualTo(FlowOutcome.WalletErrorAcknowledged("access_denied", "too late"))
        assertThat(flow.handleWalletResponse(presented.id, presentation)).isEqualTo(FlowOutcome.Expired)
        assertThat(flow.awaitOutcome(erred.id)).isEqualTo(FlowOutcome.Expired)
        assertThat(flow.awaitOutcome(presented.id)).isEqualTo(FlowOutcome.Expired)
    }

    @Test
    fun `closing a flow closes the store it created, and only that one`() {
        val owning = OpenId4VpVerificationFlow.withInMemoryStore(config, SdJwtVcCredentialVerifier(), clock)
        val started = owning.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        owning.close()
        assertThat(owning.awaitOutcome(started.id)).isEqualTo(FlowOutcome.Unknown)

        val shared = RetainingTransactionStore()
        val borrowing = OpenId4VpVerificationFlow(config, SdJwtVcCredentialVerifier(), shared, clock)
        val kept = borrowing.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        borrowing.close()
        assertThat(shared.get(kept.id)).isNotNull()
    }

    @Test
    fun `a retaining store still refuses to consume an expired response code`() {
        // A shared store may RETAIN expired entries: expiry must be a precondition of
        // consumption itself, not a side effect of the in-memory sweep.
        val retaining = RetainingTransactionStore()
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
}
