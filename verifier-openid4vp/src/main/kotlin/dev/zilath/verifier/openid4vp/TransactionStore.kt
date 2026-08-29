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
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
 * Keeps in-flight transactions between [VerificationFlow.start] and the wallet response.
 * The default is [InMemoryTransactionStore]; production deployments may plug a shared
 * store, but nothing here ever contains credential data — only nonces and outcomes.
 */
interface TransactionStore {
    /** Stores [transaction], replacing any entry with the same id. */
    fun put(transaction: Transaction)

    /**
     * Returns the stored transaction, or null if it is absent.
     *
     * An EXPIRED transaction MUST still be returned once, so the flow can tell "expired"
     * apart from "never existed"; returning null for every expired entry loses that
     * distinction and makes [VerificationFlow.awaitOutcome] answer Unknown where it should
     * answer Expired. Null is allowed only when a concurrent cleanup got there first —
     * that race is unavoidable, not a licence to skip the rule. Whatever is returned for an
     * expired entry must carry no claims. That is not
     * laxity: [VerificationFlow.awaitOutcome] needs to tell "this expired" apart from
     * "no such transaction", and it can only do that if the entry survives long enough to
     * be seen once. Implementations that return null for an expired entry will make the
     * flow answer [FlowOutcome.Unknown] where it should answer [FlowOutcome.Expired].
     *
     * What an implementation MUST NOT do is keep expired entries indefinitely: they hold
     * the disclosed claims. Remove them promptly — and do not let repeated reads of the
     * same expired entry postpone its removal.
     */
    fun get(id: TransactionId): Transaction?

    /**
     * Atomically applies [update] to the stored transaction and returns the previous
     * value, or null if absent. Used to consume the nonce exactly once.
     */
    fun compareAndUpdate(
        id: TransactionId,
        update: (Transaction) -> Transaction,
    ): Transaction?

    /** Drops the transaction if present. Idempotent. */
    fun remove(id: TransactionId)
}

/**
 * Where a transaction is in its lifecycle. Only [CREATED] accepts a wallet response
 * carrying a PRESENTATION: in any other state the nonce has already been spent and the
 * submission is rejected as a replay.
 *
 * Wallet ERROR responses are the documented exception — they are acknowledged whatever the
 * state, because an error grants nothing and OpenID4VP requires the acknowledgement
 * (§8.2). An already recorded outcome is never overwritten by one.
 */
enum class TransactionState { CREATED, PRESENTED, VERIFIED, REJECTED }

/**
 * One in-flight verification.
 *
 * The presentation itself is NEVER stored: it is verified and dropped inside
 * [dev.zilath.verifier.core.CredentialVerifier.verify]. What does live here until the
 * transaction is consumed or expires is [outcome], and for a success that carries the
 * DISCLOSED CLAIMS — they have to survive somewhere between the wallet's POST and the
 * checkout's poll of [VerificationFlow.awaitOutcome].
 *
 * So this is short-lived, but it is not empty. With the default in-memory store the claims
 * stay in the process for at most the transaction time to live. Anyone plugging in a SHARED
 * store (Redis and the like) is putting those claims on that infrastructure, and must treat
 * it accordingly — encryption at rest, no persistence to disk, no backups.
 */
data class Transaction(
    val id: TransactionId,
    val nonce: String,
    val state: TransactionState,
    val createdAt: Instant,
    val request: PresentationRequest,
    val outcome: FlowOutcome? = null,
    val mode: FlowMode = FlowMode.CROSS_DEVICE,
    /** Single-use same-device return code; cleared when consumed. */
    val responseCode: String? = null,
    /** True once the user-agent came back through the response-code exchange (WP_094). */
    val returned: Boolean = false,
) {
    /**
     * Whether [now] is strictly after `createdAt + timeToLive`. The boundary instant
     * itself still counts as valid.
     */
    fun isExpired(
        now: Instant,
        timeToLive: Duration,
    ): Boolean = createdAt.plus(timeToLive).isBefore(now)
}

/** Thread-safe in-memory store with lazy expiry, suitable for a single-node deployment. */
class InMemoryTransactionStore(
    private val clock: Clock,
    private val timeToLive: Duration,
) : TransactionStore {
    private val transactions = ConcurrentHashMap<TransactionId, Transaction>()

    override fun put(transaction: Transaction) {
        sweepExpired()
        transactions[transaction.id] = transaction
    }

    override fun get(id: TransactionId): Transaction? {
        val found = transactions[id]
        // Sweep on read as well as on put. The flow deliberately still sees THIS entry when
        // it has expired, so it can answer "expired" rather than "never existed" — but
        // without this, a process that starts no new transaction, a venue after the last
        // performance, kept every other completed transaction and the disclosed claims
        // inside them in the heap until it restarted.
        // Sweep the OTHERS; this one is consumed just below, atomically. Sweeping it here
        // too would make the conditional remove always fail and turn every expired read
        // into "unknown", which is the distinction the contract exists to preserve.
        sweepExpired(except = id)
        // An expired entry answers at most one more read, so the flow can usually say
        // "expired" rather than "never existed", and is gone from the store before that
        // answer is returned. At most, not exactly: a concurrent start() sweeps on put and
        // may take it first, and the caller then sees "unknown". Holding a side registry of
        // tombstones would make that guarantee exact, and it would add state to the one
        // component in this library that holds anything sensitive, to improve a diagnostic
        // message. Not worth it: both answers are terminal and neither carries claims. The
        // tombstone is the answer, not the stored value: redacting a copy while leaving the
        // original in the map would have looked like a fix and retained the claims anyway.
        if (found == null || !found.isExpired(clock.instant(), timeToLive)) return found
        // Only the caller whose conditional remove SUCCEEDS gets the tombstone. Ignoring
        // that boolean let two concurrent reads both receive one, which leaks nothing but
        // makes the sentence above false — and a contract the code does not keep is how
        // the next person builds on something that is not there.
        return if (transactions.remove(id, found)) found.copy(outcome = tombstoneOf(found.outcome)) else null
    }

    /** An expired outcome keeps its kind and loses everything a person could be found in. */
    private fun tombstoneOf(outcome: FlowOutcome?): FlowOutcome? =
        when (outcome) {
            null -> null
            is FlowOutcome.Verified -> FlowOutcome.Rejected(RejectionReason.EXPIRED, "outcome expired")
            is FlowOutcome.Rejected -> FlowOutcome.Rejected(outcome.reason, null)
            // The description came from the wallet response; it has no business outliving
            // the transaction it belonged to.
            is FlowOutcome.WalletErrorAcknowledged -> outcome.copy(description = null)
            // The description came from the wallet response; it has no business outliving
            // the transaction it belonged to.
            else -> outcome
        }

    override fun compareAndUpdate(
        id: TransactionId,
        update: (Transaction) -> Transaction,
    ): Transaction? {
        var previous: Transaction? = null
        transactions.computeIfPresent(id) { _, current ->
            previous = current
            update(current)
        }
        return previous
    }

    override fun remove(id: TransactionId) {
        transactions.remove(id)
    }

    private fun sweepExpired(except: TransactionId? = null) {
        val now = clock.instant()
        // Completed transactions keep their outcome until they expire, so the checkout
        // can still poll it; expiry is the only thing that removes entries.
        transactions.values
            .filter { it.isExpired(now, timeToLive) && it.id != except }
            .forEach { transactions.remove(it.id) }
    }
}
