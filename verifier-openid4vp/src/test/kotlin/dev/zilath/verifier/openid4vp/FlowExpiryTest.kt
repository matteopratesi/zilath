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
import dev.zilath.verifier.core.CredentialVerifier
import dev.zilath.verifier.core.RawPresentation
import dev.zilath.verifier.core.RejectionReason
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import dev.zilath.verifier.core.TestVectors
import dev.zilath.verifier.core.VerificationContext
import dev.zilath.verifier.core.VerificationResult
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
        flow.handleWalletResponse(started.id, walletBody(started)).outcome
        clock.advance(Duration.ofMinutes(6))
        val outcome = flow.awaitOutcome(started.id, started.pollToken)
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
        flow
            .handleWalletResponse(
                started.id,
                DirectPostBody(mapOf("error" to "access_denied", "error_description" to "user said no")),
            ).outcome
        clock.advance(Duration.ofMinutes(6))
        val outcome = flow.awaitOutcome(started.id, started.pollToken)
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
        assertThat(flow.awaitOutcome(started.id, started.pollToken)).isEqualTo(FlowOutcome.Expired)
        assertThat(flow.handleWalletResponse(started.id, body).outcome).isEqualTo(FlowOutcome.Expired)
        assertThat(flow.awaitOutcome(started.id, started.pollToken)).isEqualTo(FlowOutcome.Expired)
        assertThat(flow.requestJwtFor(started.id)).isNull()
    }

    @Test
    fun `an unreturned same-device outcome expires instead of leaking`() {
        val started = flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val handled = flow.handleWalletResponse(started.id, DirectPostBody(mapOf("error" to "access_denied")))
        assertThat(handled.outcome).isInstanceOf(FlowOutcome.WalletErrorAcknowledged::class.java)
        val code = checkNotNull(handled.redirectUri).substringAfter("response_code=")
        // The user never comes back within the transaction TTL.
        clock.advance(config.transactionTimeToLive.plusSeconds(1))
        // No code is handed out for an expired transaction, not even to a later error.
        assertThat(flow.handleWalletResponse(started.id, DirectPostBody(mapOf("error" to "access_denied"))).redirectUri)
            .isNull()
        // The stale code is not consumable, and the wallet outcome is never exposed.
        assertThat(flow.awaitOutcome(started.id, started.pollToken)).isEqualTo(FlowOutcome.Expired)
        assertThat(flow.consumeResponseCode(started.id, code)).isNull()
        assertThat(flow.awaitOutcome(started.id, started.pollToken)).isEqualTo(FlowOutcome.Expired)
    }

    @Test
    fun `a verified outcome is never read past the time to live, whatever the store keeps`() {
        // awaitOutcome returned a recorded outcome before looking at the clock, and left the
        // redaction to the store: one that kept entries longer — a TTL of its own, a
        // periodic cleanup — kept the claims readable for as long as it kept the entry.
        val retaining = RetainingTransactionStore()
        val retainingFlow = OpenId4VpVerificationFlow(config, SdJwtVcCredentialVerifier(), retaining, clock)

        val crossDevice = retainingFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        retainingFlow.handleWalletResponse(crossDevice.id, walletBody(crossDevice, source = retainingFlow)).outcome

        val sameDevice =
            retainingFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), FlowMode.SAME_DEVICE)
        val handled = retainingFlow.handleWalletResponse(sameDevice.id, walletBody(sameDevice, source = retainingFlow))
        val code = checkNotNull(handled.redirectUri).substringAfter("response_code=")
        val reader = checkNotNull(retainingFlow.consumeResponseCode(sameDevice.id, code))
        assertThat(retainingFlow.awaitOutcome(sameDevice.id, reader)).isInstanceOf(FlowOutcome.Verified::class.java)

        clock.advance(config.transactionTimeToLive.plusSeconds(1))
        for ((id, token) in listOf(crossDevice.id to crossDevice.pollToken, sameDevice.id to reader)) {
            val late = retainingFlow.awaitOutcome(id, token)
            assertThat(late).isEqualTo(FlowOutcome.Rejected(RejectionReason.EXPIRED))
            // ...and redacted where it is kept, not only in the answer.
            assertThat(retaining.get(id)?.outcome).isEqualTo(FlowOutcome.Rejected(RejectionReason.EXPIRED))
            assertThat(retaining.get(id)?.responseCode).isNull()
            assertThat(retainingFlow.awaitOutcome(id, token)).isEqualTo(late)
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
            flow
                .handleWalletResponse(
                    erred.id,
                    DirectPostBody(mapOf("error" to "access_denied", "error_description" to "too late")),
                ).outcome
        // Still acknowledged to the wallet: OpenID4VP §8.2 owes the error an answer.
        assertThat(ack).isEqualTo(FlowOutcome.WalletErrorAcknowledged("access_denied", "too late"))
        assertThat(flow.handleWalletResponse(presented.id, presentation).outcome).isEqualTo(FlowOutcome.Expired)
        assertThat(flow.awaitOutcome(erred.id, erred.pollToken)).isEqualTo(FlowOutcome.Expired)
        assertThat(flow.awaitOutcome(presented.id, presented.pollToken)).isEqualTo(FlowOutcome.Expired)
    }

    @Test
    fun `closing a flow closes the store it created, and only that one`() {
        val owning = OpenId4VpVerificationFlow.withInMemoryStore(config, SdJwtVcCredentialVerifier(), clock)
        val started = owning.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        owning.close()
        assertThat(owning.awaitOutcome(started.id, started.pollToken)).isEqualTo(FlowOutcome.Unknown)

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
            retainingFlow.handleWalletResponse(
                started.id,
                DirectPostBody(mapOf("error" to "access_denied")),
            )
        val code = checkNotNull(cancelled.redirectUri).substringAfter("response_code=")
        clock.advance(config.transactionTimeToLive.plusSeconds(1))
        // The retained entry is findable, but the stale code must not complete the flow.
        assertThat(retainingFlow.consumeResponseCode(started.id, code)).isNull()
        assertThat(retainingFlow.awaitOutcome(started.id, started.pollToken)).isEqualTo(FlowOutcome.Expired)
    }

    @Test
    fun `a verification that ends after the time to live leaves nothing behind`() {
        // The outcome of a verification finishing past expiresAt — a slow status list, a slow
        // trust evaluator — used to be written, claims and all, into the expired entry, to
        // stay there until something next read the transaction.
        val retaining = RetainingTransactionStore()
        val slow =
            object : CredentialVerifier {
                private val real = SdJwtVcCredentialVerifier()

                override fun verify(
                    presentation: RawPresentation,
                    ctx: VerificationContext,
                ): VerificationResult =
                    real.verify(presentation, ctx).also { clock.advance(config.transactionTimeToLive.plusSeconds(1)) }
            }
        val slowFlow = OpenId4VpVerificationFlow(config, slow, retaining, clock)
        for (mode in FlowMode.entries) {
            val started = slowFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), mode)
            val handled = slowFlow.handleWalletResponse(started.id, walletBody(started, source = slowFlow))
            // The wallet is told the transaction expired, and gets no return ticket.
            assertThat(handled.outcome).isEqualTo(FlowOutcome.Expired)
            assertThat(handled.redirectUri).isNull()
            val stored = checkNotNull(retaining.get(started.id))
            assertThat(stored.outcome).isNull()
            assertThat(stored.responseCode).isNull()
            assertThat(stored.responseEncryptionKey).isNull()
            assertThat(slowFlow.awaitOutcome(started.id, started.pollToken)).isEqualTo(FlowOutcome.Expired)
        }
    }

    @Test
    fun `every call that finds a transaction expired redacts it`() {
        // Not only the poll that owns it: a request object fetch, a response code, a poll
        // with a wrong token — whatever touches an expired transaction takes the claims and
        // the key out of the store, and answers nothing more than before.
        val retaining = RetainingTransactionStore()
        val retainingFlow = OpenId4VpVerificationFlow(config, SdJwtVcCredentialVerifier(), retaining, clock)

        fun verifiedAndExpired(): StartedTransaction {
            val started = retainingFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
            retainingFlow.handleWalletResponse(started.id, walletBody(started, source = retainingFlow))
            assertThat(retaining.get(started.id)?.outcome).isInstanceOf(FlowOutcome.Verified::class.java)
            return started
        }
        val fetched = verifiedAndExpired()
        val coded = verifiedAndExpired()
        val guessed = verifiedAndExpired()
        val unanswered = retainingFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        clock.advance(config.transactionTimeToLive.plusSeconds(1))

        assertThat(retainingFlow.requestJwtFor(fetched.id)).isNull()
        assertThat(retainingFlow.consumeResponseCode(coded.id, "any-code")).isNull()
        assertThat(retainingFlow.awaitOutcome(guessed.id, PollToken("wrong"))).isEqualTo(FlowOutcome.Unknown)
        assertThat(retainingFlow.requestJwtFor(unanswered.id)).isNull()
        for (id in listOf(fetched.id, coded.id, guessed.id)) {
            assertThat(
                retaining.get(id)?.outcome,
            ).describedAs(id.value).isEqualTo(FlowOutcome.Rejected(RejectionReason.EXPIRED))
        }
        assertThat(retaining.get(unanswered.id)?.responseEncryptionKey).isNull()
    }
}
