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
package dev.varco.demo

import dev.varco.verifier.openid4vp.PresentationRequest
import dev.varco.verifier.openid4vp.StartedTransaction
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference

/**
 * Demo-side bookkeeping of started transactions: time-bounded (lazy sweep on insert,
 * like the flow's own store) and holding at most ONE issued receipt per transaction,
 * so its signed timestamp reflects when the outcome was first observed — not each download.
 */
internal class DemoTransactionRegistry(
    private val clock: Clock,
    private val timeToLive: Duration,
) {
    internal class Entry(
        val transaction: StartedTransaction,
        val request: PresentationRequest,
        val createdAt: Instant,
    ) {
        val receipt: AtomicReference<String?> = AtomicReference(null)
    }

    private val entries = ConcurrentHashMap<String, Entry>()

    fun register(
        transaction: StartedTransaction,
        request: PresentationRequest,
    ) {
        sweep()
        entries[transaction.id.value] = Entry(transaction, request, clock.instant())
    }

    fun get(txId: String): Entry? = entries[txId]

    /** Issues the receipt at most once per transaction; later calls return the same JWS. */
    fun receiptFor(
        txId: String,
        issue: (PresentationRequest) -> String,
    ): String? =
        entries[txId]?.let { entry ->
            entry.receipt.updateAndGet { existing -> existing ?: issue(entry.request) }
        }

    private fun sweep() {
        val now = clock.instant()
        entries.values.removeIf { it.createdAt.plus(timeToLive).isBefore(now) }
    }
}
