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

import dev.varco.verifier.core.TestVectors
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Duration

class InMemoryTransactionStoreTest {
    private val clock = SteppingClock(TestVectors.NOW)
    private val store = InMemoryTransactionStore(clock, Duration.ofMinutes(5))

    private fun transaction(id: String) =
        Transaction(
            id = TransactionId(id),
            nonce = "nonce-$id",
            state = TransactionState.CREATED,
            createdAt = clock.instant(),
            request = PresentationRequest.forTestPid("urn:varco:test:entitlement"),
        )

    @Test
    fun `expired transactions are swept on the next put`() {
        store.put(transaction("old"))
        clock.advance(Duration.ofMinutes(6))
        store.put(transaction("fresh"))
        assertThat(store.get(TransactionId("old"))).isNull()
        assertThat(store.get(TransactionId("fresh"))).isNotNull()
    }

    @Test
    fun `compareAndUpdate returns the previous value and applies the update`() {
        store.put(transaction("tx"))
        val previous =
            store.compareAndUpdate(TransactionId("tx")) { it.copy(state = TransactionState.PRESENTED) }
        assertThat(previous?.state).isEqualTo(TransactionState.CREATED)
        assertThat(store.get(TransactionId("tx"))?.state).isEqualTo(TransactionState.PRESENTED)
    }

    @Test
    fun `compareAndUpdate on a missing transaction returns null`() {
        assertThat(store.compareAndUpdate(TransactionId("ghost")) { it }).isNull()
    }

    @Test
    fun `remove deletes the transaction`() {
        store.put(transaction("tx"))
        store.remove(TransactionId("tx"))
        assertThat(store.get(TransactionId("tx"))).isNull()
    }
}
