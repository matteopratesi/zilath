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

import com.sun.net.httpserver.HttpServer
import dev.zilath.verifier.core.HttpDocumentFetcher.Destinations
import dev.zilath.verifier.trust.FederationDocumentNotFoundException
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * The demo's federation fetcher answers as the fetcher contract asks: a document the server
 * says does not exist is the federation's answer, anything else that fails is an outage.
 * The difference decides whether the offline fallback may stand in for a withdrawn statement.
 * And it reaches this machine only for a federation that lives on it.
 */
class HttpFetcherTest {
    private val server =
        // The address the URLs below name: the JVM's loopback address may be ::1 instead.
        HttpServer.create(InetSocketAddress(InetAddress.getByName(LOOPBACK), 0), 0).apply {
            for (status in listOf(200, 404, 410, 500)) {
                createContext("/$status") { exchange ->
                    val body = "status $status".toByteArray()
                    exchange.sendResponseHeaders(status, body.size.toLong())
                    exchange.responseBody.use { it.write(body) }
                }
            }
            start()
        }

    private val base = "http://$LOOPBACK:${server.address.port}"

    @AfterEach
    fun stop() = server.stop(0)

    @Test
    fun `a document the server says does not exist is the federation's answer`() {
        for (status in listOf(404, 410)) {
            assertThatThrownBy { httpFetcher(insecureTls = false, LOCAL_ANCHOR).fetch("$base/$status") }
                .describedAs("HTTP $status")
                .isInstanceOf(FederationDocumentNotFoundException::class.java)
        }
    }

    @Test
    fun `any other failure is not taken for a withdrawal`() {
        assertThatThrownBy { httpFetcher(insecureTls = false, LOCAL_ANCHOR).fetch("$base/500") }
            .isNotInstanceOf(FederationDocumentNotFoundException::class.java)
            .hasMessage("the server answered 500")
        assertThat(httpFetcher(insecureTls = false, LOCAL_ANCHOR).fetch("$base/200")).isEqualTo("status 200")
    }

    @Test
    fun `a demo pointed at a remote federation reaches nothing on this machine`() {
        for (path in listOf("200", "404")) {
            assertThatThrownBy { httpFetcher(insecureTls = false, REMOTE_ANCHOR).fetch("$base/$path") }
                .describedAs(path)
                .isNotInstanceOf(FederationDocumentNotFoundException::class.java)
                .hasMessageContaining("refused:")
        }
    }

    @Test
    fun `with trust-all TLS nothing but loopback is reached`() {
        assertThatThrownBy { httpFetcher(insecureTls = true, LOCAL_ANCHOR).fetch("https://ta.example/.well-known") }
            .isInstanceOf(IllegalStateException::class.java)
            .hasMessage("insecure TLS is restricted to loopback, refused for ta.example")
    }

    @Test
    fun `trust-all TLS connects to loopback alone, a local federation adds it, a real one never`() {
        assertThat(destinationsFor(insecureTls = true, LOCAL_ANCHOR)).isEqualTo(Destinations.LOOPBACK)
        assertThat(destinationsFor(insecureTls = true, REMOTE_ANCHOR)).isEqualTo(Destinations.LOOPBACK)
        assertThat(destinationsFor(insecureTls = false, LOCAL_ANCHOR)).isEqualTo(Destinations.PUBLIC_AND_LOOPBACK)
        assertThat(destinationsFor(insecureTls = false, REMOTE_ANCHOR)).isEqualTo(Destinations.PUBLIC)
    }

    private companion object {
        const val LOOPBACK = "127.0.0.1"
        const val LOCAL_ANCHOR = "https://localhost:3001"
        const val REMOTE_ANCHOR = "https://ta.wallet.ipzs.it"
    }
}
