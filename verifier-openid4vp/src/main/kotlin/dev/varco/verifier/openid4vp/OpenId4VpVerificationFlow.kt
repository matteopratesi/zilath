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
package dev.varco.verifier.openid4vp

import dev.varco.verifier.core.CredentialVerifier
import dev.varco.verifier.core.RawPresentation
import dev.varco.verifier.core.RejectionReason
import dev.varco.verifier.core.VerificationContext
import dev.varco.verifier.core.VerificationResult
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
                before.isExpired(clock.instant(), config.transactionTimeToLive) -> FlowOutcome.Expired
                before.state != TransactionState.CREATED ->
                    FlowOutcome.Rejected(RejectionReason.REPLAY, "transaction nonce already consumed")
                walletError != null ->
                    FlowOutcome.WalletErrorAcknowledged(walletError, body.parameters["error_description"])
                else -> verifyResponse(before, body)
            }
        record(txId, before, outcome)
        return outcome
    }

    override fun awaitOutcome(txId: TransactionId): FlowOutcome {
        val transaction = store.get(txId) ?: return FlowOutcome.Unknown
        return when {
            // Same-device: the transaction is complete only when the user-agent has come
            // back through the response-code exchange (WP_094) — until then, pending.
            transaction.mode == FlowMode.SAME_DEVICE &&
                transaction.outcome != null &&
                !transaction.returned &&
                !transaction.isExpired(clock.instant(), config.transactionTimeToLive) ->
                FlowOutcome.Pending
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
        // been processed: the ack to the wallet is the only place it belongs.
        val eligible =
            callbackBase != null &&
                transaction != null &&
                transaction.mode == FlowMode.SAME_DEVICE &&
                transaction.outcome != null
        if (!eligible) return null
        val code = transaction.responseCode ?: assignResponseCode(txId)
        return code?.let { "$callbackBase?response_code=$it" }
    }

    /** Idempotent under concurrency: whoever sets the code first wins. */
    private fun assignResponseCode(txId: TransactionId): String? {
        val fresh = randomToken(RESPONSE_CODE_BYTES)
        store.compareAndUpdate(txId) { current ->
            if (current.responseCode == null && !current.returned) current.copy(responseCode = fresh) else current
        }
        return store.get(txId)?.responseCode
    }

    override fun consumeResponseCode(code: String): TransactionId? {
        val transaction = if (code.isBlank()) null else store.findByResponseCode(code)
        if (transaction == null) return null
        // Single use: only the caller that observes the code still present wins, and the
        // return state is set in the same atomic step (WP_094).
        val before =
            store.compareAndUpdate(transaction.id) { current ->
                if (current.responseCode == code) {
                    current.copy(responseCode = null, returned = true)
                } else {
                    current
                }
            }
        return transaction.id.takeIf { before?.responseCode == code }
    }

    private fun verifyResponse(
        transaction: Transaction,
        body: DirectPostBody,
    ): FlowOutcome =
        runCatching {
            val payload = config.profile.decodeWalletResponse(body, config)
            checkState(payload, transaction)
            val compact = extractPresentation(payload, transaction.request.credentialQueryId)
            val context =
                VerificationContext(
                    expectedNonce = transaction.nonce,
                    expectedAudience = config.clientId,
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
