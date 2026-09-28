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
package dev.zilath.verifier.trust

import com.sun.net.httpserver.HttpServer
import dev.zilath.verifier.core.DocumentNotFoundException
import dev.zilath.verifier.core.HttpDocumentFetcher
import dev.zilath.verifier.core.HttpDocumentFetcher.Destinations
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * The federation fetcher tells the evaluator what it needs to know: a withdrawn document
 * is the federation's answer, and everything else — a refused destination included — is a
 * federation not reached, which only the offline fallback may answer for.
 */
class HttpFederationFetcherTest {
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

    private val local = HttpFederationFetcher(HttpDocumentFetcher(destinations = Destinations.LOOPBACK))

    @AfterEach
    fun stop() = server.stop(0)

    @Test
    fun `a withdrawn document is the federation's answer`() {
        for (status in listOf(404, 410)) {
            assertThatThrownBy { local.fetch("$base/$status") }
                .describedAs("HTTP $status")
                .isInstanceOf(FederationDocumentNotFoundException::class.java)
                .hasMessage("the server answered $status")
                .hasCauseInstanceOf(DocumentNotFoundException::class.java)
        }
    }

    @Test
    fun `any other failure is a federation not reached`() {
        assertThat(local.fetch("$base/200")).isEqualTo("status 200")
        assertThatThrownBy { local.fetch("$base/500") }
            .isNotInstanceOf(FederationDocumentNotFoundException::class.java)
            .hasMessage("the server answered 500")
        // The default refuses loopback: a destination refused is not a document withdrawn.
        assertThatThrownBy { HttpFederationFetcher().fetch("$base/404") }
            .isNotInstanceOf(FederationDocumentNotFoundException::class.java)
            .hasMessageContaining("refused:")
    }

    private companion object {
        const val LOOPBACK = "127.0.0.1"
    }
}
