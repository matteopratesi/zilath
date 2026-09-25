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

import dev.zilath.verifier.core.TestVectors
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.time.Duration

class InMemoryTransactionStoreTest {
    private val clock = SteppingClock(TestVectors.NOW)
    private val store = InMemoryTransactionStore(clock, 10, ManualScheduler())

    /** Runs the background sweep only when told to. */
    private class ManualScheduler : SweepScheduler {
        val tasks = mutableListOf<Runnable>()
        var closed = 0

        override fun schedule(
            period: Duration,
            task: Runnable,
        ): AutoCloseable {
            assertThat(period).isEqualTo(InMemoryTransactionStore.SWEEP_PERIOD)
            tasks += task
            return AutoCloseable { closed++ }
        }

        fun runAll() = tasks.forEach(Runnable::run)
    }

    private fun transaction(
        id: String,
        timeToLive: Duration = Duration.ofMinutes(5),
    ) = Transaction(
        id = TransactionId(id),
        nonce = "nonce-$id",
        state = TransactionState.CREATED,
        createdAt = clock.instant(),
        expiresAt = clock.instant().plus(timeToLive),
        request = PresentationRequest.forTestPid("urn:zilath:test:entitlement"),
    )

    @Test
    fun `an expired entry is kept a minute longer, then swept`() {
        store.put(transaction("old"))
        // Expired, but inside the retention: still there, so the flow can say "expired".
        clock.advance(Duration.ofMinutes(5).plus(InMemoryTransactionStore.EXPIRED_RETENTION))
        store.put(transaction("fresh"))
        assertThat(store.get(TransactionId("old"))).isNotNull()
        clock.advance(Duration.ofSeconds(1))
        store.put(transaction("fresher"))
        assertThat(store.get(TransactionId("old"))).isNull()
        assertThat(store.get(TransactionId("fresh"))).isNotNull()
    }

    @Test
    fun `an entry lives as long as its own expiry says, not as long as the store likes`() {
        // The store used to apply a time to live of its own, independent of the flow's: a
        // shorter one dropped transactions whose request object the wallet still held.
        store.put(transaction("long", timeToLive = Duration.ofMinutes(50)))
        clock.advance(Duration.ofMinutes(45))
        store.put(transaction("other"))
        assertThat(store.get(TransactionId("long"))).isNotNull()
    }

    @Test
    fun `an idle store sweeps its expired entries on its own`() {
        // Removal used to happen only inside put and get: a process that took no further
        // request — a venue after the last performance — kept its last verified outcomes,
        // claims and all, in the heap until it restarted.
        val scheduler = ManualScheduler()
        val idle = InMemoryTransactionStore(clock, 10, scheduler)
        idle.put(transaction("done"))
        clock.advance(Duration.ofMinutes(5).plus(InMemoryTransactionStore.EXPIRED_RETENTION).plusSeconds(1))
        assertThat(idle.size).isEqualTo(1)
        scheduler.runAll()
        assertThat(idle.size).isZero()
    }

    @Test
    fun `closing the store stops its sweep and drops what it holds`() {
        val scheduler = ManualScheduler()
        val closing = InMemoryTransactionStore(clock, 10, scheduler)
        closing.put(transaction("held"))
        closing.close()
        assertThat(scheduler.closed).isEqualTo(1)
        assertThat(closing.get(TransactionId("held"))).isNull()
    }

    @Test
    fun `a full store refuses a new transaction until room is made`() {
        val small = InMemoryTransactionStore(clock, 2, ManualScheduler())
        small.put(transaction("a"))
        small.put(transaction("b", timeToLive = Duration.ofMinutes(30)))
        assertThatThrownBy { small.put(transaction("c")) }.isInstanceOf(TooManyTransactionsException::class.java)
        // Replacing an entry is not growth.
        small.put(transaction("a"))
        clock.advance(Duration.ofMinutes(5).plus(InMemoryTransactionStore.EXPIRED_RETENTION).plusSeconds(1))
        small.put(transaction("c"))
        assertThat(small.get(TransactionId("a"))).isNull()
        assertThat(small.get(TransactionId("b"))).isNotNull()
        assertThatThrownBy { InMemoryTransactionStore(clock, 0) }.isInstanceOf(IllegalArgumentException::class.java)
    }

    @Test
    fun `a read costs the same with twenty thousand live transactions as with a thousand`() {
        // Every put and get used to scan the whole map: a cost linear in the live
        // transactions on requests no one authenticates for, and quadratic to fill.
        fun costOfReads(live: Int): Long {
            val filled = InMemoryTransactionStore(clock, live + 1, ManualScheduler())
            repeat(live) { filled.put(transaction("tx-$it")) }
            val ghost = TransactionId("ghost")
            repeat(READS) { filled.get(ghost) }
            return (1..RUNS).minOf {
                val started = System.nanoTime()
                repeat(READS) { filled.get(ghost) }
                System.nanoTime() - started
            }
        }
        val small = costOfReads(1_000)
        val large = costOfReads(20_000)
        // A floor keeps timer noise on a very small `small` from failing the ratio.
        assertThat(large).isLessThan(maxOf(small * 8, Duration.ofMillis(5).toNanos()))
    }

    @Test
    fun `the shared sweep thread exists only while some store is open`() {
        val scheduler = SharedDaemonSweepScheduler("zilath-test-sweeper")
        val first = InMemoryTransactionStore(clock, 10, scheduler)
        val second = InMemoryTransactionStore(clock, 10, scheduler)
        assertThat(scheduler.running).isTrue()
        val threads = Thread.getAllStackTraces().keys.filter { it.name == "zilath-test-sweeper" }
        assertThat(threads).hasSize(1).allSatisfy { assertThat(it.isDaemon).isTrue() }
        first.close()
        assertThat(scheduler.running).isTrue()
        second.close()
        second.close()
        assertThat(scheduler.running).isFalse()
    }

    private companion object {
        const val READS = 500
        const val RUNS = 5
    }
}
