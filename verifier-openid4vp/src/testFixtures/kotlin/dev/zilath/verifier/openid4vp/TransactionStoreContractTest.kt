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

import dev.zilath.verifier.core.DisclosedClaims
import dev.zilath.verifier.core.RejectionReason
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * The conformance kit for a [TransactionStore]: the properties the flow relies on, as the
 * KDoc of [TransactionStore] numbers them, each checked against YOUR implementation.
 *
 * ```kotlin
 * class RedisTransactionStoreTest : TransactionStoreContractTest() {
 *     override fun newStore(): TransactionStore = RedisTransactionStore(testRedis)
 * }
 * ```
 *
 * Every test gets a fresh store from [newStore] and hands it to [release] afterwards. The
 * transactions it writes expire an hour from now, so a store that enforces expiry of its
 * own keeps them for the whole run.
 */
abstract class TransactionStoreContractTest {
    /** A new, empty store. */
    protected abstract fun newStore(): TransactionStore

    /** Releases what [newStore] opened; the default does nothing. */
    protected open fun release(store: TransactionStore) = Unit

    private lateinit var store: TransactionStore

    @BeforeEach
    fun openStore() {
        store = newStore()
    }

    @AfterEach
    fun releaseStore() {
        release(store)
    }

    @Test
    fun `compareAndUpdate returns the value it replaced, not the one it stored`() {
        val stored = sampleTransaction("tx-previous")
        store.put(stored)
        val previous = store.compareAndUpdate(stored.id) { it.copy(state = TransactionState.PRESENTED) }
        assertThat(previous).isEqualTo(stored)
        assertThat(store.get(stored.id)?.state).isEqualTo(TransactionState.PRESENTED)
    }

    @Test
    fun `compareAndUpdate on an absent id returns null and stores nothing`() {
        val ghost = TransactionId("tx-ghost")
        assertThat(store.compareAndUpdate(ghost) { sampleTransaction("tx-ghost") }).isNull()
        assertThat(store.get(ghost)).isNull()
    }

    @Test
    fun `get sees every write that has returned`() {
        val stored = sampleTransaction("tx-ryw")
        store.put(stored)
        assertThat(store.get(stored.id)).isEqualTo(stored)
        store.compareAndUpdate(stored.id) { it.copy(state = TransactionState.PRESENTED) }
        assertThat(store.get(stored.id)?.state).isEqualTo(TransactionState.PRESENTED)
        store.compareAndUpdate(stored.id) { it.copy(returned = true) }
        assertThat(store.get(stored.id)?.returned).isTrue()
        store.remove(stored.id)
        assertThat(store.get(stored.id)).isNull()
    }

    @Test
    fun `put replaces the entry with the same id`() {
        val first = sampleTransaction("tx-replace")
        store.put(first)
        val second = first.copy(nonce = "a-different-nonce")
        store.put(second)
        assertThat(store.get(first.id)).isEqualTo(second)
    }

    @Test
    fun `remove is idempotent and leaves other entries alone`() {
        val removed = sampleTransaction("tx-removed")
        val kept = sampleTransaction("tx-kept")
        store.put(removed)
        store.put(kept)
        store.remove(removed.id)
        store.remove(removed.id)
        store.remove(TransactionId("tx-never-there"))
        assertThat(store.get(removed.id)).isNull()
        assertThat(store.get(kept.id)).isEqualTo(kept)
    }

    @Test
    fun `a transaction reads back equal to what was written, whatever its outcome`() {
        sampleOutcomes().forEachIndexed { index, outcome ->
            val written = sampleTransaction("tx-roundtrip-$index").copy(outcome = outcome)
            store.put(written)
            assertThat(store.get(written.id)).describedAs("get of %s", outcome).isEqualTo(written)
            assertThat(store.compareAndUpdate(written.id) { it })
                .describedAs("compareAndUpdate of %s", outcome)
                .isEqualTo(written)
            assertThat(store.get(written.id)).describedAs("get after update of %s", outcome).isEqualTo(written)
        }
    }

    @Test
    fun `concurrent updates of one id are neither lost nor applied twice`() {
        val stored = sampleTransaction("tx-concurrent").copy(nonce = "")
        store.put(stored)
        val seen = Collections.synchronizedList(mutableListOf<String>())
        runConcurrently(THREADS) {
            repeat(UPDATES_PER_THREAD) {
                val previous = store.compareAndUpdate(stored.id) { it.copy(nonce = it.nonce + "x") }
                seen += checkNotNull(previous) { "the entry vanished" }.nonce
            }
        }
        // Each committed update saw a distinct predecessor, and the final value counts them all.
        assertThat(store.get(stored.id)?.nonce).hasSize(THREADS * UPDATES_PER_THREAD)
        assertThat(seen.toSet()).hasSize(THREADS * UPDATES_PER_THREAD)
    }

    @Test
    fun `exactly one concurrent caller moves a transaction out of CREATED`() {
        repeat(ROUNDS) { round ->
            val stored = sampleTransaction("tx-race-$round")
            store.put(stored)
            val winners =
                java.util.concurrent.atomic
                    .AtomicInteger()
            runConcurrently(THREADS) {
                val previous =
                    store.compareAndUpdate(stored.id) { current ->
                        if (current.state == TransactionState.CREATED) {
                            current.copy(state = TransactionState.PRESENTED)
                        } else {
                            current
                        }
                    }
                if (previous?.state == TransactionState.CREATED) winners.incrementAndGet()
            }
            assertThat(winners.get()).describedAs("round %d", round).isEqualTo(1)
        }
    }

    /**
     * A transaction with every field set, expiring an hour from now. Instants are whole
     * milliseconds: the contract asks for no finer precision.
     */
    protected open fun sampleTransaction(id: String): Transaction {
        val now = Instant.now().truncatedTo(ChronoUnit.MILLIS)
        return Transaction(
            id = TransactionId(id),
            nonce = "nonce-$id-0123456789abcdefghijklmnopqrstuvwxyz",
            state = TransactionState.CREATED,
            createdAt = now,
            expiresAt = now.plus(1, ChronoUnit.HOURS),
            request = PresentationRequest.forVct("urn:zilath:test:entitlement", listOf("given_name"), "pid"),
            pollTokenHash = "poll-token-hash-$id",
            outcome = null,
            mode = FlowMode.SAME_DEVICE,
            responseCode = "response-code-$id",
            returned = false,
        )
    }

    /** One of each outcome the flow records, with claims a lossy codec would get wrong. */
    protected open fun sampleOutcomes(): List<FlowOutcome?> =
        listOf(
            null,
            FlowOutcome.Verified(
                DisclosedClaims(
                    Json
                        .parseToJsonElement(
                            """{"vct": "urn:zilath:test:entitlement", "iss": "https://issuer.example",
                                "given_name": "Zoë Ñúñez 中文", "entitled": true, "count": 3,
                                "big": 9007199254740993, "ratio": 1.5, "missing": null,
                                "address": {"locality": "Roma", "codes": [1, "2", false]}}""",
                        ).jsonObject,
                ),
            ),
            FlowOutcome.Rejected(RejectionReason.NONCE_MISMATCH, "key binding nonce does not match"),
            FlowOutcome.Rejected(RejectionReason.EXPIRED),
            FlowOutcome.WalletErrorAcknowledged("access_denied", "the holder declined"),
            FlowOutcome.WalletErrorAcknowledged("access_denied"),
        )

    private fun runConcurrently(
        threads: Int,
        body: () -> Unit,
    ) {
        val pool = Executors.newFixedThreadPool(threads)
        try {
            val start = CountDownLatch(1)
            val futures = (1..threads).map { pool.submit { start.await().also { body() } } }
            start.countDown()
            futures.forEach { it.get(TIMEOUT_SECONDS, TimeUnit.SECONDS) }
        } finally {
            pool.shutdownNow()
        }
    }

    private companion object {
        const val THREADS = 16
        const val UPDATES_PER_THREAD = 50
        const val ROUNDS = 20
        const val TIMEOUT_SECONDS = 30L
    }
}
