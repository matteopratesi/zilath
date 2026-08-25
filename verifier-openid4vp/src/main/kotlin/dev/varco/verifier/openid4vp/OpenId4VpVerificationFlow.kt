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
    override fun start(request: PresentationRequest): StartedTransaction {
        val id = TransactionId(randomToken(TRANSACTION_ID_BYTES))
        val nonce = randomToken(NONCE_BYTES)
        store.put(Transaction(id, nonce, TransactionState.CREATED, clock.instant(), request))
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
            // A recorded outcome survives expiry: the checkout must still observe it.
            transaction.outcome != null -> transaction.outcome
            transaction.isExpired(clock.instant(), config.transactionTimeToLive) -> FlowOutcome.Expired
            else -> FlowOutcome.Pending
        }
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
