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
package dev.zilath.demo

import dev.zilath.verifier.openid4vp.PresentationRequest
import dev.zilath.verifier.openid4vp.StartedTransaction
import dev.zilath.verifier.openid4vp.TransactionId
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset

class DemoTransactionRegistryTest {
    private class MutableClock(
        private var now: Instant,
    ) : Clock() {
        fun advance(duration: Duration) {
            now += duration
        }

        override fun instant(): Instant = now

        override fun getZone() = ZoneOffset.UTC

        override fun withZone(zone: java.time.ZoneId): Clock = this
    }

    private val clock = MutableClock(Instant.parse("2026-08-24T10:00:00Z"))
    private val registry = DemoTransactionRegistry(clock, Duration.ofMinutes(15))
    private val request = PresentationRequest.forTestPid("urn:zilath:test:entitlement")

    private fun transaction(id: String) = StartedTransaction(TransactionId(id), "https://rp/req/$id", "openid4vp://x")

    @Test
    fun `expired entries are swept on the next registration`() {
        registry.register(transaction("old"), request)
        clock.advance(Duration.ofMinutes(16))
        registry.register(transaction("fresh"), request)
        assertThat(registry.get("old")).isNull()
        assertThat(registry.get("fresh")).isNotNull()
    }

    @Test
    fun `the receipt is issued exactly once and then reused`() {
        registry.register(transaction("tx"), request)
        var issued = 0
        val first =
            registry.receiptFor("tx") {
                issued++
                "receipt-$issued"
            }
        val second =
            registry.receiptFor("tx") {
                issued++
                "receipt-$issued"
            }
        assertThat(first).isEqualTo("receipt-1")
        assertThat(second).isEqualTo("receipt-1")
        assertThat(issued).isEqualTo(1)
    }

    @Test
    fun `an entry expires exactly at the TTL boundary`() {
        registry.register(transaction("edge"), request)
        clock.advance(Duration.ofMinutes(15))
        registry.register(transaction("fresh"), request)
        assertThat(registry.get("edge")).isNull()
    }

    @Test
    fun `concurrent receipt requests issue exactly once`() {
        registry.register(transaction("tx"), request)
        val issued =
            java.util.concurrent.atomic
                .AtomicInteger()
        val pool =
            java.util.concurrent.Executors
                .newFixedThreadPool(8)
        val results =
            (1..16)
                .map {
                    pool.submit<String?> {
                        registry.receiptFor("tx") {
                            issued.incrementAndGet()
                            "receipt"
                        }
                    }
                }.map { it.get() }
        pool.shutdown()
        assertThat(results).containsOnly("receipt")
        assertThat(issued.get()).isEqualTo(1)
    }

    @Test
    fun `holder names are escaped before reaching the ticket page`() {
        val html = ticketHtml("tx", "<script>alert(1)</script>")
        assertThat(html).doesNotContain("<script>alert(1)</script>")
        assertThat(html).contains("&lt;script&gt;")
    }
}
