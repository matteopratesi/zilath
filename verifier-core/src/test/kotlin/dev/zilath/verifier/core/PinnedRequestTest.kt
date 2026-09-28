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
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLContextSpi
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLServerSocketFactory
import javax.net.ssl.SSLSessionContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager

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
    fun `non-ASCII in the path and query goes out percent-encoded as UTF-8`() {
        val request = nextRequest()
        assertThat(fetcher(LOOPBACK).fetch("http://localhost:$port/café?q=è")).isEqualTo("ok")
        assertThat(request.get(WAIT_SECONDS, TimeUnit.SECONDS)).startsWith("GET /caf%C3%A9?q=%C3%A8 HTTP/1.1\r\n")
    }

    @Test
    fun `a socket is closed however opening TLS on it fails`() {
        val closedByClient =
            CompletableFuture.supplyAsync {
                server.accept().use { connection ->
                    connection.soTimeout = WAIT_SECONDS.toInt() * 1000
                    connection.getInputStream().read()
                }
            }
        val failingTls =
            HttpDocumentFetcher(
                Duration.ofSeconds(2),
                Duration.ofSeconds(5),
                HttpDocumentFetcher.DEFAULT_MAX_RESPONSE_BYTES,
                destinations = HttpDocumentFetcher.Destinations.LOOPBACK,
                sslContext = FailingTlsContext(),
                resolve = { listOf(InetAddress.getByName(LOOPBACK)) },
            )
        assertThatThrownBy { failingTls.fetch("https://localhost:$port/document") }
            .isInstanceOf(IllegalStateException::class.java)
            .hasMessage("the factory failed")
        // End of stream: the client closed the connection it could not secure.
        assertThat(closedByClient.get(WAIT_SECONDS * 2, TimeUnit.SECONDS)).isEqualTo(-1)
    }

    /** A TLS context whose socket factory fails with something other than an IOException. */
    private class FailingTlsContext : SSLContext(FailingSpi(), null, "TLS")

    private class FailingSpi : SSLContextSpi() {
        override fun engineInit(
            keys: Array<out KeyManager>?,
            trust: Array<out TrustManager>?,
            random: SecureRandom?,
        ) = Unit

        override fun engineGetSocketFactory(): SSLSocketFactory = FailingFactory()

        override fun engineGetServerSocketFactory(): SSLServerSocketFactory = unused()

        override fun engineCreateSSLEngine(): SSLEngine = unused()

        override fun engineCreateSSLEngine(
            host: String?,
            port: Int,
        ): SSLEngine = unused()

        override fun engineGetServerSessionContext(): SSLSessionContext = unused()

        override fun engineGetClientSessionContext(): SSLSessionContext = unused()
    }

    private class FailingFactory : SSLSocketFactory() {
        override fun createSocket(
            socket: Socket?,
            host: String?,
            port: Int,
            autoClose: Boolean,
        ): Socket = error("the factory failed")

        override fun getDefaultCipherSuites(): Array<String> = unused()

        override fun getSupportedCipherSuites(): Array<String> = unused()

        override fun createSocket(
            host: String?,
            port: Int,
        ): Socket = unused()

        override fun createSocket(
            host: String?,
            port: Int,
            localHost: InetAddress?,
            localPort: Int,
        ): Socket = unused()

        override fun createSocket(
            host: InetAddress?,
            port: Int,
        ): Socket = unused()

        override fun createSocket(
            address: InetAddress?,
            port: Int,
            localAddress: InetAddress?,
            localPort: Int,
        ): Socket = unused()
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

        fun unused(): Nothing = throw UnsupportedOperationException("not used by the fetcher")
    }
}
