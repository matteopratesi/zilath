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
