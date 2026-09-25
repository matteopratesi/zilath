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
import org.junit.jupiter.api.Test
import java.time.Duration

class InMemoryTransactionStoreTest {
    private val clock = SteppingClock(TestVectors.NOW)
    private val store = InMemoryTransactionStore(clock)

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
}
