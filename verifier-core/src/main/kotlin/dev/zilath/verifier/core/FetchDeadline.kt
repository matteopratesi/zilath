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
package dev.zilath.verifier.core

import java.net.http.HttpTimeoutException
import java.time.Duration

/** The instant a fetch must be done by: [total] after it began. */
internal class FetchDeadline(
    private val total: Duration,
) {
    private val endsAt = System.nanoTime() + total.toNanos()

    /** What is left of the fetch's time; [HttpTimeoutException] once nothing is. */
    fun remaining(): Duration {
        val left = endsAt - System.nanoTime()
        if (left <= 0) throw HttpTimeoutException("the fetch did not complete within $total")
        return Duration.ofNanos(left)
    }

    /** [remaining] as a socket timeout: whole milliseconds, and never zero, which means none. */
    fun remainingMillis(): Int = remaining().toMillis().coerceIn(1L, Int.MAX_VALUE.toLong()).toInt()
}
