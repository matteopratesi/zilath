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
 */
class HttpFetcherTest {
    private val server =
        HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0).apply {
            for (status in listOf(200, 404, 410, 500)) {
                createContext("/$status") { exchange ->
                    val body = "status $status".toByteArray()
                    exchange.sendResponseHeaders(status, body.size.toLong())
                    exchange.responseBody.use { it.write(body) }
                }
            }
            start()
        }

    private val base = "http://127.0.0.1:${server.address.port}"

    @AfterEach
    fun stop() = server.stop(0)

    @Test
    fun `a document the server says does not exist is the federation's answer`() {
        for (status in listOf(404, 410)) {
            assertThatThrownBy { httpFetcher(insecureTls = false).fetch("$base/$status") }
                .describedAs("HTTP $status")
                .isInstanceOf(FederationDocumentNotFoundException::class.java)
        }
    }

    @Test
    fun `any other failure is not taken for a withdrawal`() {
        assertThatThrownBy { httpFetcher(insecureTls = false).fetch("$base/500") }
            .isNotInstanceOf(FederationDocumentNotFoundException::class.java)
            .hasMessageContaining("returned 500")
        assertThat(httpFetcher(insecureTls = false).fetch("$base/200")).isEqualTo("status 200")
    }
}
