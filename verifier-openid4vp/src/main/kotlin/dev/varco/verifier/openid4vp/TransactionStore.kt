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
    fun put(transaction: Transaction)

    fun get(id: TransactionId): Transaction?

    /**
     * Atomically applies [update] to the stored transaction and returns the previous
     * value, or null if absent. Used to consume the nonce exactly once.
     */
    fun compareAndUpdate(
        id: TransactionId,
        update: (Transaction) -> Transaction,
    ): Transaction?

    fun remove(id: TransactionId)

    /** The transaction currently holding [code] as its same-device response code. */
    fun findByResponseCode(code: String): Transaction?
}

enum class TransactionState { CREATED, PRESENTED, VERIFIED, REJECTED }

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
) {
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

    override fun get(id: TransactionId): Transaction? = transactions[id]

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

    override fun findByResponseCode(code: String): Transaction? {
        sweepExpired()
        return transactions.values.firstOrNull { it.responseCode == code }
    }

    private fun sweepExpired() {
        val now = clock.instant()
        // Completed transactions keep their outcome until they expire, so the checkout
        // can still poll it; expiry is the only thing that removes entries.
        transactions.values
            .filter { it.isExpired(now, timeToLive) }
            .forEach { transactions.remove(it.id) }
    }
}
