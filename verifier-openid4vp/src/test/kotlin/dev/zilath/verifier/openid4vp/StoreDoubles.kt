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

import java.util.concurrent.atomic.AtomicReference

/**
 * A conforming store of the other common kind: optimistic, copy-on-write, retrying the
 * update function whenever another writer got in first — so the function really does run
 * more than once under contention, which the contract allows and the flow must survive.
 */
class OptimisticTransactionStore : TransactionStore {
    private val entries = AtomicReference<Map<TransactionId, Transaction>>(emptyMap())

    /** How many times an update function has been invoked, retries included. */
    @Volatile
    var updateInvocations = 0
        private set

    override fun put(transaction: Transaction) {
        entries.updateAndGet { it + (transaction.id to transaction) }
    }

    override fun get(id: TransactionId): Transaction? = entries.get()[id]

    override fun compareAndUpdate(
        id: TransactionId,
        update: (Transaction) -> Transaction,
    ): Transaction? {
        while (true) {
            val snapshot = entries.get()
            val current = snapshot[id] ?: return null
            updateInvocations++
            val next = update(current)
            if (entries.compareAndSet(snapshot, snapshot + (id to next))) return current
        }
    }

    override fun remove(id: TransactionId) {
        entries.updateAndGet { it - id }
    }
}

/**
 * A conforming store that never expires anything: what a shared store with a periodic or
 * lazy cleanup looks like between two cleanups. The flow must not depend on the store's
 * expiry for anything it promises.
 */
class RetainingTransactionStore : TransactionStore {
    private val lock = Any()
    private val entries = HashMap<TransactionId, Transaction>()

    override fun put(transaction: Transaction) {
        synchronized(lock) { entries[transaction.id] = transaction }
    }

    override fun get(id: TransactionId): Transaction? = synchronized(lock) { entries[id] }

    override fun compareAndUpdate(
        id: TransactionId,
        update: (Transaction) -> Transaction,
    ): Transaction? = synchronized(lock) { entries[id]?.also { entries[id] = update(it) } }

    override fun remove(id: TransactionId) {
        synchronized(lock) { entries.remove(id) }
    }
}

class RetainingTransactionStoreContractTest : TransactionStoreContractTest() {
    override fun newStore(): TransactionStore = RetainingTransactionStore()
}

class OptimisticTransactionStoreContractTest : TransactionStoreContractTest() {
    override fun newStore(): TransactionStore = OptimisticTransactionStore()
}

/**
 * Keeps less than it is given — the wallet's description shortened, a rejection's detail
 * dropped — as a store minimising what it holds might. It breaks the contract's lossless
 * property on purpose: the same-device return must not depend on it.
 */
class MinimisingTransactionStore : TransactionStore {
    private val delegate = RetainingTransactionStore()

    private fun minimised(transaction: Transaction): Transaction =
        transaction.copy(
            outcome =
                when (val outcome = transaction.outcome) {
                    is FlowOutcome.WalletErrorAcknowledged ->
                        outcome.copy(
                            description = outcome.description?.take(KEPT),
                        )
                    is FlowOutcome.Rejected -> outcome.copy(detail = null)
                    else -> outcome
                },
        )

    override fun put(transaction: Transaction) = delegate.put(minimised(transaction))

    override fun get(id: TransactionId): Transaction? = delegate.get(id)

    override fun compareAndUpdate(
        id: TransactionId,
        update: (Transaction) -> Transaction,
    ): Transaction? = delegate.compareAndUpdate(id) { minimised(update(it)) }

    override fun remove(id: TransactionId) = delegate.remove(id)

    private companion object {
        const val KEPT = 8
    }
}

/**
 * Atomic on the primary, but [get] is served by a replica that sees a new entry at once and
 * never catches up with an update — the read-your-writes property broken on purpose, as by
 * a replica read that lags behind the write just made.
 */
class StaleReplicaTransactionStore : TransactionStore {
    private val primary = RetainingTransactionStore()
    private val replica = RetainingTransactionStore()

    override fun put(transaction: Transaction) {
        primary.put(transaction)
        replica.put(transaction)
    }

    override fun get(id: TransactionId): Transaction? = replica.get(id)

    override fun compareAndUpdate(
        id: TransactionId,
        update: (Transaction) -> Transaction,
    ): Transaction? = primary.compareAndUpdate(id, update)

    override fun remove(id: TransactionId) {
        primary.remove(id)
        replica.remove(id)
    }
}

/**
 * A conforming store caught in one legal interleaving: when [removeDuringNextUpdate] is set,
 * the next update function runs on the current value, then the entry disappears before the
 * write — a concurrent removal — and the update returns null, having committed nothing.
 */
class RemovedDuringUpdateStore(
    private val delegate: TransactionStore,
) : TransactionStore by delegate {
    @Volatile
    var removeDuringNextUpdate = false

    @Volatile
    var updatesRun = 0
        private set

    override fun compareAndUpdate(
        id: TransactionId,
        update: (Transaction) -> Transaction,
    ): Transaction? {
        if (!removeDuringNextUpdate) return delegate.compareAndUpdate(id, update)
        removeDuringNextUpdate = false
        delegate.get(id)?.let { current ->
            update(current)
            updatesRun++
            delegate.remove(id)
        }
        return null
    }
}
