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
 * It has no time to live of its own: each transaction carries its [Transaction.expiresAt].
 * At that instant a sweep redacts the entry — the claims, the wallet's text, the response
 * code and the decryption key go, by the rule the flow applies — and [EXPIRED_RETENTION]
 * later removes it: kept that long so that the checkout is told "expired" rather than
 * "unknown". (Before 0.4.0 it took a time to live of its own, independent of the flow's: set
 * longer, it kept verified claims readable past the documented bound; set shorter, it
 * dropped transactions whose request object a wallet still held.)
 *
 * A sweep runs in [put] and in [get] — not in [compareAndUpdate] or [remove] — and in a
 * background task every [SWEEP_PERIOD], so that an idle process — a venue after the last
 * performance — does not keep the claims of its last verifications in the heap until it
 * restarts. So the claims and the key leave at most [SWEEP_PERIOD] after the transaction
 * expired, and the entry at most [EXPIRED_RETENTION] plus [SWEEP_PERIOD] after it. The
 * background sweep runs on one daemon thread shared by every store in the process, which
 * exists only while some store is open. [close] stops this store's sweep and drops what it
 * holds; a store nobody closes stops being swept once it is garbage.
 *
 * Each [VerificationFlow.start] allocates an entry here, on behalf of whoever reaches the
 * page that calls it: at most [maxTransactions] are held (expired ones included, until
 * removed), and beyond that [put] throws [TooManyTransactionsException]. The footprint is
 * the rate of starts times the time to live, plus the minute of retention; limit or bind to
 * a session what may call `start()`.
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
     * When each entry is due for redaction (at its expiry) and for removal (a minute later),
     * soonest first. The fourth internal review found every put and get scanning the whole
     * map: a cost linear in the live transactions on requests nobody has to authenticate for,
     * and quadratic to fill. Now a sweep looks at the heads of these queues and touches only
     * what is due.
     */
    private val redactions = PriorityBlockingQueue<Due>(INITIAL_QUEUE_CAPACITY, compareBy(Due::at))
    private val removals = PriorityBlockingQueue<Due>(INITIAL_QUEUE_CAPACITY, compareBy(Due::at))
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
        schedule(transaction)
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
        // The flow never moves expiresAt; if a caller does, the entry needs its own due times.
        if (next != null && next.expiresAt != previous?.expiresAt) schedule(next)
        return previous
    }

    override fun remove(id: TransactionId) {
        transactions.remove(id)
    }

    /** Stops the background sweep and drops every entry: nothing held here outlives the store. */
    override fun close() {
        backgroundSweep.close()
        transactions.clear()
        redactions.clear()
        removals.clear()
    }

    /** How many entries the store holds, expired ones included. */
    internal val size: Int get() = transactions.size

    /**
     * Redacts what has expired and removes what is due. One sweeper at a time; the others
     * go on without waiting.
     */
    internal fun sweepExpired() {
        if (!sweeping.tryLock()) return
        try {
            val now = clock.instant()
            // At expiry the claims, the wallet's text, the response code and the decryption key
            // go, by the flow's own rule: an expired entry that nobody reads — an abandoned
            // transaction, a checkout that stopped polling — no longer keeps them for the
            // minute of retention.
            drainDue(
                redactions,
                now,
            ) { current -> if (current.isExpired(now)) current.redactedForExpiry() else current }
            // The entry may have been replaced since: remove it only if IT is due.
            drainDue(removals, now) { current -> current.takeUnless { removalTimeOf(it).isBefore(now) } }
        } finally {
            sweeping.unlock()
        }
    }

    private fun drainDue(
        queue: PriorityBlockingQueue<Due>,
        now: Instant,
        change: (Transaction) -> Transaction?,
    ) {
        while (queue.peek()?.at?.isBefore(now) == true) {
            val due = queue.poll()
            transactions.computeIfPresent(due.id) { _, current -> change(current) }
        }
    }

    private fun schedule(transaction: Transaction) {
        redactions.add(Due(transaction.expiresAt, transaction.id))
        removals.add(Due(removalTimeOf(transaction), transaction.id))
    }

    private fun removalTimeOf(transaction: Transaction): Instant = transaction.expiresAt.plus(EXPIRED_RETENTION)

    private class Due(
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
