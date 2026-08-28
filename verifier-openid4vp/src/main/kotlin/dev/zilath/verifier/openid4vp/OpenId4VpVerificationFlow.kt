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

import dev.zilath.verifier.core.CredentialVerifier
import dev.zilath.verifier.core.RawPresentation
import dev.zilath.verifier.core.RejectionReason
import dev.zilath.verifier.core.VerificationContext
import dev.zilath.verifier.core.VerificationResult
import java.time.Clock

/**
 * Default [VerificationFlow] implementation (plan docs/03 §5-M0.3).
 *
 * State machine per transaction: CREATED -> PRESENTED -> VERIFIED | REJECTED.
 * The nonce is consumed atomically on the first wallet response: any further
 * response is rejected as [RejectionReason.REPLAY] without touching the stored
 * outcome, and the checkout keeps polling the first result.
 */
class OpenId4VpVerificationFlow(
    private val config: RelyingPartyConfiguration,
    private val verifier: CredentialVerifier,
    private val store: TransactionStore,
    private val clock: Clock,
) : VerificationFlow {
    override fun start(
        request: PresentationRequest,
        mode: FlowMode,
    ): StartedTransaction {
        require(mode == FlowMode.CROSS_DEVICE || config.endpoints.sameDeviceCallbackBase != null) {
            "same-device transactions need RpEndpoints.sameDeviceCallbackBase"
        }
        val id = TransactionId(randomToken(TRANSACTION_ID_BYTES))
        val nonce = randomToken(NONCE_BYTES)
        store.put(Transaction(id, nonce, TransactionState.CREATED, clock.instant(), request, mode = mode))
        val requestUri = "${config.endpoints.requestUriBase}/${id.value}"
        return StartedTransaction(id, requestUri, qrPayloadOf(config, requestUri))
    }

    override fun requestJwtFor(txId: TransactionId): String? {
        val transaction = store.get(txId)
        return when {
            transaction == null -> null
            transaction.state != TransactionState.CREATED -> null
            transaction.isExpired(clock.instant(), config.transactionTimeToLive) -> null
            else -> buildRequestJwt(config, transaction, clock.instant())
        }
    }

    override fun handleWalletResponse(
        txId: TransactionId,
        body: DirectPostBody,
    ): FlowOutcome {
        val before =
            store.compareAndUpdate(txId) { current ->
                if (current.state == TransactionState.CREATED) {
                    current.copy(state = TransactionState.PRESENTED)
                } else {
                    current
                }
            } ?: return FlowOutcome.Unknown
        val walletError = body.parameters["error"]
        val outcome =
            when {
                // OpenID4VP §8.2: an authorization ERROR response is acknowledged, always.
                // It grants nothing, so its state does not matter — and `record` below
                // refuses to clobber an outcome that was already reached.
                walletError != null ->
                    FlowOutcome.WalletErrorAcknowledged(walletError, body.parameters["error_description"])
                before.isExpired(clock.instant(), config.transactionTimeToLive) -> FlowOutcome.Expired
                before.state != TransactionState.CREATED ->
                    FlowOutcome.Rejected(RejectionReason.REPLAY, "transaction nonce already consumed")
                else -> verifyResponse(before, body)
            }
        record(txId, before, outcome)
        return outcome
    }

    override fun awaitOutcome(txId: TransactionId): FlowOutcome {
        val transaction = store.get(txId) ?: return FlowOutcome.Unknown
        return when {
            // Same-device: the transaction is complete only when the user-agent has come
            // back through the response-code exchange (WP_094) — pending until then, and
            // EXPIRED (never the wallet outcome) when the return leg never happened.
            transaction.mode == FlowMode.SAME_DEVICE &&
                transaction.outcome != null &&
                !transaction.returned ->
                if (transaction.isExpired(clock.instant(), config.transactionTimeToLive)) {
                    FlowOutcome.Expired
                } else {
                    FlowOutcome.Pending
                }
            // A recorded outcome survives expiry: the checkout must still observe it.
            transaction.outcome != null -> transaction.outcome
            transaction.isExpired(clock.instant(), config.transactionTimeToLive) -> FlowOutcome.Expired
            else -> FlowOutcome.Pending
        }
    }

    override fun sameDeviceRedirectFor(txId: TransactionId): String? {
        val callbackBase = config.endpoints.sameDeviceCallbackBase
        val transaction = store.get(txId)
        // The redirect exists only for a same-device transaction whose response has
        // been processed: the ack to the wallet is the only place it belongs. After the
        // return leg no further redirect exists, and an expired transaction gets no
        // code either — its callback could never complete the flow.
        val eligible =
            callbackBase != null &&
                transaction != null &&
                transaction.mode == FlowMode.SAME_DEVICE &&
                transaction.outcome != null &&
                !transaction.returned &&
                !transaction.isExpired(clock.instant(), config.transactionTimeToLive)
        if (!eligible) return null
        val code = transaction.responseCode ?: assignResponseCode(txId)
        // The session id travels as the last path segment, the code as the query: the
        // callback can then reject an unknown session apart from an invalid code.
        return code?.let { "$callbackBase/${txId.value}?response_code=$it" }
    }

    /** Idempotent under concurrency: whoever sets the code first wins. */
    private fun assignResponseCode(txId: TransactionId): String? {
        val fresh = randomToken(RESPONSE_CODE_BYTES)
        store.compareAndUpdate(txId) { current ->
            if (current.responseCode == null && !current.returned) current.copy(responseCode = fresh) else current
        }
        return store.get(txId)?.responseCode
    }

    override fun consumeResponseCode(
        txId: TransactionId,
        code: String,
    ): Boolean {
        if (code.isBlank()) return false
        // The decision is taken INSIDE the atomic update, once, and the code must belong
        // to THIS transaction: presenting another transaction's code here leaves it
        // untouched, so its own return leg still works.
        var consumed = false
        store.compareAndUpdate(txId) { current ->
            val eligible =
                current.responseCode == code &&
                    !current.isExpired(clock.instant(), config.transactionTimeToLive)
            consumed = eligible
            if (eligible) current.copy(responseCode = null, returned = true) else current
        }
        return consumed
    }

    private fun verifyResponse(
        transaction: Transaction,
        body: DirectPostBody,
    ): FlowOutcome =
        runCatching {
            val payload = config.profile.decodeWalletResponse(body, config)
            checkState(payload, transaction)
            checkEchoedNonce(payload, transaction)
            val compact = extractPresentation(payload, transaction.request.credentialQueryId)
            val context =
                VerificationContext(
                    expectedNonce = transaction.nonce,
                    expectedAudiences = acceptedAudiencesFor(config.clientId),
                    clock = clock,
                    trustEvaluator = config.trustEvaluator,
                    statusChecker = config.statusChecker,
                )
            when (val result = verifier.verify(RawPresentation.SdJwtVcPresentation(compact), context)) {
                is VerificationResult.Verified -> FlowOutcome.Verified(result.claims)
                is VerificationResult.Rejected -> FlowOutcome.Rejected(result.reason, result.detail)
            }
        }.getOrElse { failure ->
            when (failure) {
                is FlowRejection -> FlowOutcome.Rejected(failure.reason, failure.detail)
                else -> {
                    // Application-supplied TrustEvaluator/StatusChecker beans may throw anything:
                    // the transaction must still reach a terminal state (its nonce is consumed),
                    // and internals must not leak towards the wallet.
                    logger.log(System.Logger.Level.ERROR, "verification pipeline failure", failure)
                    FlowOutcome.Rejected(RejectionReason.INTERNAL_ERROR, "verification pipeline failure")
                }
            }
        }

    private fun record(
        txId: TransactionId,
        before: Transaction,
        outcome: FlowOutcome,
    ) {
        when {
            // A replayed response must not clobber the first, recorded outcome.
            before.state != TransactionState.CREATED -> Unit
            outcome is FlowOutcome.Expired -> store.remove(txId)
            else ->
                store.compareAndUpdate(txId) { current ->
                    val state =
                        when (outcome) {
                            is FlowOutcome.Verified -> TransactionState.VERIFIED
                            else -> TransactionState.REJECTED
                        }
                    current.copy(state = state, outcome = outcome)
                }
        }
    }

    companion object {
        private val logger = System.getLogger(OpenId4VpVerificationFlow::class.java.name)

        private const val TRANSACTION_ID_BYTES = 16

        /** 32 random bytes -> 43 base64url chars, above the 32-char minimum of the profile. */
        private const val NONCE_BYTES = 32

        /** The same-device response_code is a bearer return ticket: same entropy as the nonce. */
        private const val RESPONSE_CODE_BYTES = 32

        /** Convenience factory wiring the default in-memory store. */
        fun withInMemoryStore(
            config: RelyingPartyConfiguration,
            verifier: CredentialVerifier,
            clock: Clock = Clock.systemUTC(),
        ): OpenId4VpVerificationFlow =
            OpenId4VpVerificationFlow(
                config,
                verifier,
                InMemoryTransactionStore(clock, config.transactionTimeToLive),
                clock,
            )
    }
}
