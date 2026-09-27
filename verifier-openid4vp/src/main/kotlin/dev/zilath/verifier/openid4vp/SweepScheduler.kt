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

import java.time.Duration
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** Runs a store's periodic sweep; a seam so tests can run the sweep by hand. */
internal fun interface SweepScheduler {
    /** Runs [task] every [period] until the returned handle is closed. Closing twice is harmless. */
    fun schedule(
        period: Duration,
        task: Runnable,
    ): AutoCloseable
}

/**
 * One daemon thread for every store in the process, started with the first open store and
 * stopped with the last: no thread per store, none left behind once every store is closed
 * or collected — in a test run, or when a servlet container undeploys the application.
 */
internal class SharedDaemonSweepScheduler(
    private val threadName: String,
) : SweepScheduler {
    private var executor: ScheduledThreadPoolExecutor? = null
    private var active = 0

    /** Whether the thread currently exists. */
    val running: Boolean
        @Synchronized get() = executor != null

    @Synchronized
    override fun schedule(
        period: Duration,
        task: Runnable,
    ): AutoCloseable {
        val pool = executor ?: newExecutor().also { executor = it }
        // A periodic task that throws is silently never run again, and would never be
        // counted as closed: the sweep must not throw.
        val safe = Runnable { runCatching { task.run() } }
        val future = pool.scheduleWithFixedDelay(safe, period.toMillis(), period.toMillis(), TimeUnit.MILLISECONDS)
        active++
        return AutoCloseable { release(future) }
    }

    @Synchronized
    private fun release(future: ScheduledFuture<*>) {
        if (!future.cancel(false)) return
        active--
        if (active == 0) {
            executor?.shutdown()
            executor = null
        }
    }

    private fun newExecutor(): ScheduledThreadPoolExecutor =
        ScheduledThreadPoolExecutor(1) { runnable ->
            Thread(runnable, threadName).apply { isDaemon = true }
        }.apply { removeOnCancelPolicy = true }

    companion object {
        val DEFAULT = SharedDaemonSweepScheduler("zilath-transaction-sweeper")
    }
}
