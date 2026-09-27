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

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.UnknownHostException
import java.net.http.HttpTimeoutException
import java.time.Duration
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors

class HttpDocumentFetcherTest {
    /** Every path the server was asked for, in order. */
    private val requested = ConcurrentLinkedQueue<String>()

    private val server =
        // The address the URLs below name: the JVM's loopback address may be ::1 instead.
        HttpServer.create(InetSocketAddress(InetAddress.getByName(LOOPBACK), 0), 0).apply {
            executor = Executors.newCachedThreadPool()
            createContext("/") { exchange ->
                requested += exchange.requestURI.path
                exchange.use { answer(it) }
            }
            start()
        }

    private val base = "http://$LOOPBACK:${server.address.port}"

    /** Names the tests resolve, and every name the fetcher asked to resolve. */
    private val names =
        mapOf(
            "public.example" to listOf("93.184.215.14"),
            "internal.example" to listOf("10.0.0.5"),
            "metadata.example" to listOf("169.254.169.254"),
            "mixed.example" to listOf("93.184.215.14", "192.168.1.10"),
            "nothing.example" to emptyList(),
        )
    private val resolved = ConcurrentLinkedQueue<String>()

    private fun fetcher(allowLoopback: Boolean = true) =
        HttpDocumentFetcher(
            connectTimeout = Duration.ofSeconds(2),
            totalTimeout = TOTAL_TIMEOUT,
            maxResponseBytes = LIMIT,
            allowLoopback = allowLoopback,
            sslContext = null,
            resolve = { host ->
                resolved += host
                names[host]?.map(InetAddress::getByName) ?: InetAddress.getAllByName(host).toList()
            },
        )

    @AfterEach
    fun stop() = server.stop(0)

    @Test
    fun `a 200 is the document`() {
        assertThat(fetcher().fetch("$base/document")).isEqualTo("the document")
    }

    @Test
    fun `404 and 410 are the server saying there is no such document, anything else a failure`() {
        for (status in listOf(404, 410)) {
            assertThatThrownBy { fetcher().fetch("$base/status/$status") }
                .describedAs("HTTP $status")
                .isInstanceOf(DocumentNotFoundException::class.java)
                .hasMessage("the server answered $status")
        }
        for (status in listOf(204, 500, 503)) {
            assertThatThrownBy { fetcher().fetch("$base/status/$status") }
                .describedAs("HTTP $status")
                .isInstanceOf(IOException::class.java)
                .isNotInstanceOf(DocumentNotFoundException::class.java)
                .hasMessage("the server answered $status")
        }
    }

    @Test
    fun `a redirect is a failure, and its target is never asked for`() {
        assertThatThrownBy { fetcher().fetch("$base/redirect") }
            .isInstanceOf(IOException::class.java)
            .isNotInstanceOf(DocumentNotFoundException::class.java)
            .hasMessage("the server answered 302")
        assertThat(requested).containsExactly("/redirect")
    }

    @Test
    fun `a body longer than the limit is refused, declared or not`() {
        for (path in listOf("/large-declared", "/large-chunked")) {
            assertThatThrownBy { fetcher().fetch("$base$path") }
                .describedAs(path)
                .isInstanceOf(IOException::class.java)
                .hasMessageContaining("response larger than $LIMIT bytes")
        }
        assertThat(fetcher().fetch("$base/at-limit")).hasSize(LIMIT)
    }

    @Test
    fun `a declared length over the limit is refused before the body is read`() {
        // The server declares too much, sends a little and stalls: only the declared length
        // can refuse it before the timeout.
        assertThatThrownBy { fetcher().fetch("$base/large-declared-stalling") }
            .isInstanceOf(IOException::class.java)
            .isNotInstanceOf(HttpTimeoutException::class.java)
            .hasMessageContaining("response larger than $LIMIT bytes")
    }

    @Test
    fun `a response that does not arrive whole in time is abandoned`() {
        for (path in listOf("/slow-headers", "/slow-body")) {
            val started = System.nanoTime()
            assertThatThrownBy { fetcher().fetch("$base$path") }
                .describedAs(path)
                .isInstanceOf(HttpTimeoutException::class.java)
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(STALL)
        }
    }

    @Test
    fun `a host that resolves to an internal address is refused before anything is sent`() {
        val refusing = fetcher(allowLoopback = false)
        for (url in listOf(
            "https://internal.example/.well-known/openid-federation",
            "https://metadata.example/latest/meta-data/",
            "https://mixed.example/status/1",
            "https://nothing.example/status/1",
            "$base/document",
            "http://localhost:${server.address.port}/document",
        )) {
            assertThatThrownBy { refusing.fetch(url) }
                .describedAs(url)
                .isInstanceOf(IOException::class.java)
                .hasMessageContaining("refused:")
                .hasMessageContaining("resolves to an address this fetcher does not reach")
        }
        assertThat(requested).isEmpty()
    }

    @Test
    fun `a URL outside the shape rule is refused before its host is even resolved`() {
        for (url in listOf(
            "http://public.example/status/1",
            "https://10.0.0.5/status/1",
            "https://2130706433/status/1",
            "https://user@public.example/status/1",
            "https://public.example/status/1#fragment",
            "ftp://public.example/status/1",
            "not a url",
        )) {
            assertThatThrownBy { fetcher().fetch(url) }
                .describedAs(url)
                .isInstanceOf(IOException::class.java)
                .hasMessage("refused: not a URL this fetcher dereferences")
        }
        assertThat(resolved).isEmpty()
    }

    @Test
    fun `a name that does not resolve is a failure, not a missing document`() {
        val unresolvable =
            HttpDocumentFetcher(
                Duration.ofSeconds(2),
                TOTAL_TIMEOUT,
                LIMIT,
                allowLoopback = false,
                sslContext = null,
                resolve = { throw UnknownHostException(it) },
            )
        assertThatThrownBy { unresolvable.fetch("https://gone.example/status/1") }
            .isInstanceOf(UnknownHostException::class.java)
    }

    @Test
    fun `the bounds must be positive`() {
        assertThatThrownBy { HttpDocumentFetcher(connectTimeout = Duration.ZERO) }
            .isInstanceOf(IllegalArgumentException::class.java)
        assertThatThrownBy { HttpDocumentFetcher(totalTimeout = Duration.ofSeconds(-1)) }
            .isInstanceOf(IllegalArgumentException::class.java)
        assertThatThrownBy { HttpDocumentFetcher(maxResponseBytes = 0) }
            .isInstanceOf(IllegalArgumentException::class.java)
    }

    private fun answer(exchange: HttpExchange) {
        val path = exchange.requestURI.path
        when {
            path == "/document" -> exchange.send(200, "the document".toByteArray())
            path.startsWith("/status/") -> exchange.sendStatus(path.removePrefix("/status/").toInt())
            path == "/redirect" -> {
                exchange.responseHeaders.add("Location", "/document")
                exchange.sendStatus(302)
            }
            path == "/large-declared" -> exchange.send(200, ByteArray(LIMIT + 1))
            path == "/large-chunked" -> {
                exchange.sendResponseHeaders(200, 0)
                runCatching { repeat(4) { exchange.responseBody.write(ByteArray(LIMIT / 2)) } }
            }
            path == "/at-limit" -> exchange.send(200, ByteArray(LIMIT) { 'a'.code.toByte() })
            path == "/large-declared-stalling" -> {
                exchange.sendResponseHeaders(200, LIMIT + 1L)
                runCatching {
                    exchange.responseBody.write(ByteArray(PARTIAL))
                    exchange.responseBody.flush()
                }
                Thread.sleep(STALL.toMillis())
            }
            path == "/slow-headers" -> Thread.sleep(STALL.toMillis())
            path == "/slow-body" -> {
                exchange.sendResponseHeaders(200, 0)
                exchange.responseBody.write("the begin".toByteArray())
                exchange.responseBody.flush()
                Thread.sleep(STALL.toMillis())
            }
            else -> exchange.sendStatus(404)
        }
    }

    private fun HttpExchange.send(
        status: Int,
        body: ByteArray,
    ) {
        sendResponseHeaders(status, body.size.toLong())
        runCatching { responseBody.write(body) }
    }

    private fun HttpExchange.sendStatus(status: Int) = sendResponseHeaders(status, -1)

    private companion object {
        const val LOOPBACK = "127.0.0.1"
        const val LIMIT = 1024
        const val PARTIAL = 16
        val TOTAL_TIMEOUT: Duration = Duration.ofMillis(500)

        /** How long the slow handlers stall: well past the timeout. */
        val STALL: Duration = Duration.ofSeconds(3)
    }
}
