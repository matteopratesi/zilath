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

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/** What goes on the wire: one GET, for the URL's path and query, and nothing to negotiate. */
class PinnedRequestTest {
    private val server = ServerSocket().apply { bind(InetSocketAddress(InetAddress.getByName(LOOPBACK), 0)) }
    private val port = server.localPort

    /** The next request the server receives, as text, once it has answered it. */
    private fun nextRequest(): CompletableFuture<String> =
        CompletableFuture.supplyAsync {
            server.accept().use { connection ->
                val request = ByteArrayOutputStream()
                val input = connection.getInputStream()
                var byte = input.read()
                while (byte != -1) {
                    request.write(byte)
                    if (request.toString(Charsets.US_ASCII).endsWith("\r\n\r\n")) break
                    byte = input.read()
                }
                connection.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".toByteArray())
                request.toString(Charsets.US_ASCII)
            }
        }

    /** Resolves every name to [addresses], in order. */
    private fun fetcher(vararg addresses: String) =
        HttpDocumentFetcher(
            Duration.ofSeconds(2),
            Duration.ofSeconds(5),
            HttpDocumentFetcher.DEFAULT_MAX_RESPONSE_BYTES,
            destinations = HttpDocumentFetcher.Destinations.LOOPBACK,
            sslContext = null,
            resolve = { addresses.map(InetAddress::getByName) },
        )

    @AfterEach
    fun stop() = server.close()

    @Test
    fun `the request asks for the path and query, the body as it is, and a closed connection`() {
        val request = nextRequest()
        assertThat(fetcher(LOOPBACK).fetch("http://localhost:$port/status/1?x=1&y=%20")).isEqualTo("ok")
        assertThat(request.get(WAIT_SECONDS, TimeUnit.SECONDS)).isEqualTo(
            "GET /status/1?x=1&y=%20 HTTP/1.1\r\n" +
                "Host: localhost:$port\r\n" +
                "Accept-Encoding: identity\r\n" +
                "Connection: close\r\n" +
                "\r\n",
        )
    }

    @Test
    fun `a URL without a path asks for the root`() {
        val request = nextRequest()
        assertThat(fetcher(LOOPBACK).fetch("http://localhost:$port")).isEqualTo("ok")
        assertThat(request.get(WAIT_SECONDS, TimeUnit.SECONDS)).startsWith("GET / HTTP/1.1\r\n")
    }

    @Test
    fun `an address that does not accept gives way to the next one checked`() {
        val request = nextRequest()
        // Nothing listens on the IPv6 loopback at this port: the connection fails there first.
        assertThat(fetcher("::1", LOOPBACK).fetch("http://localhost:$port/document")).isEqualTo("ok")
        assertThat(request.get(WAIT_SECONDS, TimeUnit.SECONDS)).startsWith("GET /document HTTP/1.1\r\n")
    }

    private companion object {
        const val LOOPBACK = "127.0.0.1"
        const val WAIT_SECONDS = 5L
    }
}
