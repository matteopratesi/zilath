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

import java.time.Clock
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap

/**
 * Thread-safe in-memory [TransactionStore], suitable for a single-node deployment.
 *
 * It has no time to live of its own: each transaction carries its [Transaction.expiresAt],
 * and an entry is removed [EXPIRED_RETENTION] after it — long enough for the checkout to be
 * told "expired" rather than "unknown", with the claims already redacted by the flow if
 * anything read the entry in between. (Before 0.4.0 it took a time to live of its own,
 * independent of the flow's: set longer, it kept verified claims readable past the
 * documented bound; set shorter, it dropped transactions whose request object a wallet
 * still held.)
 */
class InMemoryTransactionStore(
    private val clock: Clock,
) : TransactionStore {
    private val transactions = ConcurrentHashMap<TransactionId, Transaction>()

    override fun put(transaction: Transaction) {
        sweepExpired()
        transactions[transaction.id] = transaction
    }

    override fun get(id: TransactionId): Transaction? {
        // Sweeping on read as well as on put: without it, a process that starts no new
        // transaction — a venue after the last performance — kept every completed one, and
        // the claims inside, until it restarted.
        sweepExpired()
        return transactions[id]
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

    private fun sweepExpired() {
        val now = clock.instant()
        transactions.values
            .filter { it.expiresAt.plus(EXPIRED_RETENTION).isBefore(now) }
            .forEach { transactions.remove(it.id, it) }
    }

    companion object {
        /** How long an expired entry is kept, so that a late poll reads "expired", not "unknown". */
        val EXPIRED_RETENTION: Duration = Duration.ofMinutes(1)
    }
}
