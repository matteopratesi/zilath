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

import java.lang.ref.WeakReference
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.PriorityBlockingQueue
import java.util.concurrent.locks.ReentrantLock

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
 *
 * Removal happens on every operation AND on a background sweep every [SWEEP_PERIOD], so an
 * idle process — a venue after the last performance — does not keep the claims of its last
 * verifications in the heap until it restarts: they leave the store at most
 * [EXPIRED_RETENTION] plus [SWEEP_PERIOD] after the transaction expired. The sweep runs on
 * one daemon thread shared by every store in the process, which exists only while some
 * store is open. [close] stops this store's sweep and drops what it holds; a store nobody
 * closes stops being swept once it is garbage.
 *
 * Each [VerificationFlow.start] allocates an entry here, on behalf of whoever reaches the
 * page that calls it: at most [maxTransactions] are held (expired ones included, until
 * removed), and beyond that [put] throws [TooManyTransactionsException]. The footprint is
 * the rate of starts times the time to live; limit or bind to a session what may call
 * `start()`.
 */
class InMemoryTransactionStore internal constructor(
    private val clock: Clock,
    private val maxTransactions: Int,
    scheduler: SweepScheduler,
) : TransactionStore,
    AutoCloseable {
    /**
     * A store on [clock] holding at most [maxTransactions] entries, swept in the background
     * on the shared daemon thread.
     */
    constructor(clock: Clock, maxTransactions: Int = DEFAULT_MAX_TRANSACTIONS) :
        this(clock, maxTransactions, SharedDaemonSweepScheduler.DEFAULT)

    init {
        require(maxTransactions > 0) { "maxTransactions must be positive" }
    }

    private val transactions = ConcurrentHashMap<TransactionId, Transaction>()

    /**
     * When each entry is due for removal, soonest first. The fourth internal review found
     * every put and get scanning the whole map: a cost linear in the live transactions on
     * requests nobody has to authenticate for, and quadratic to fill. Now an operation looks
     * at the head of this queue and removes only what is due.
     */
    private val removals = PriorityBlockingQueue<Removal>(INITIAL_QUEUE_CAPACITY, compareBy(Removal::at))
    private val sweeping = ReentrantLock()
    private val backgroundSweep: AutoCloseable = WeakSweep(this).let { it.start(scheduler) }

    override fun put(transaction: Transaction) {
        sweepExpired()
        // Checked before the insert, so under concurrent starts the bound can be passed by
        // as many entries as there are threads inserting at that instant — not more.
        if (transactions.size >= maxTransactions && !transactions.containsKey(transaction.id)) {
            throw TooManyTransactionsException(maxTransactions)
        }
        transactions[transaction.id] = transaction
        removals.add(Removal(removalTimeOf(transaction), transaction.id))
    }

    override fun get(id: TransactionId): Transaction? {
        sweepExpired()
        return transactions[id]
    }

    override fun compareAndUpdate(
        id: TransactionId,
        update: (Transaction) -> Transaction,
    ): Transaction? {
        var previous: Transaction? = null
        val next =
            transactions.computeIfPresent(id) { _, current ->
                previous = current
                update(current)
            }
        // The flow never moves expiresAt; if a caller does, the entry needs a removal of its own.
        if (next != null && next.expiresAt != previous?.expiresAt) removals.add(Removal(removalTimeOf(next), id))
        return previous
    }

    override fun remove(id: TransactionId) {
        transactions.remove(id)
    }

    /** Stops the background sweep and drops every entry: nothing held here outlives the store. */
    override fun close() {
        backgroundSweep.close()
        transactions.clear()
        removals.clear()
    }

    /** How many entries the store holds, expired ones included. */
    internal val size: Int get() = transactions.size

    /** Removes what is due. One sweeper at a time; the others go on without waiting. */
    internal fun sweepExpired() {
        if (!sweeping.tryLock()) return
        try {
            val now = clock.instant()
            while (removals.peek()?.at?.isBefore(now) == true) {
                val due = removals.poll()
                // The entry may have been replaced since: remove it only if IT is due.
                transactions.computeIfPresent(due.id) { _, current ->
                    current.takeUnless { removalTimeOf(it).isBefore(now) }
                }
            }
        } finally {
            sweeping.unlock()
        }
    }

    private fun removalTimeOf(transaction: Transaction): Instant = transaction.expiresAt.plus(EXPIRED_RETENTION)

    private class Removal(
        val at: Instant,
        val id: TransactionId,
    )

    /**
     * The background sweep holds its store WEAKLY: a store nobody closed does not stay
     * reachable, and swept, for the life of the process because a timer points at it.
     */
    private class WeakSweep(
        store: InMemoryTransactionStore,
    ) : Runnable {
        private val store = WeakReference(store)

        @Volatile
        private var handle: AutoCloseable? = null

        fun start(scheduler: SweepScheduler): AutoCloseable =
            scheduler.schedule(SWEEP_PERIOD, this).also { handle = it }

        override fun run() {
            val target = store.get()
            if (target == null) handle?.close() else target.sweepExpired()
        }
    }

    companion object {
        /** How long an expired entry is kept, so that a late poll reads "expired", not "unknown". */
        val EXPIRED_RETENTION: Duration = Duration.ofMinutes(1)

        /** How often an idle store is swept. */
        val SWEEP_PERIOD: Duration = Duration.ofSeconds(30)

        /**
         * Ten thousand: at the default five-minute time to live, about thirty starts a second
         * sustained. More than one node sees at that rate needs a shared store anyway.
         */
        const val DEFAULT_MAX_TRANSACTIONS: Int = 10_000

        private const val INITIAL_QUEUE_CAPACITY = 64
    }
}

/** Thrown by a store that refuses a new transaction because it is full. */
class TooManyTransactionsException(
    limit: Int,
) : IllegalStateException("the transaction store holds its maximum of $limit transactions")
