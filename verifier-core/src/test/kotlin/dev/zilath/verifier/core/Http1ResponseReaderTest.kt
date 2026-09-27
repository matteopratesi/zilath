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
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.IOException

class Http1ResponseReaderTest {
    private fun read(
        raw: String,
        limit: Int = LIMIT,
    ): PinnedResponse = Http1ResponseReader(ByteArrayInputStream(raw.toByteArray(Charsets.ISO_8859_1)), limit).read()

    private fun bodyOf(raw: String) = read(raw).body?.toString(Charsets.ISO_8859_1)

    @Test
    fun `a 200 body is read as its framing says`() {
        assertThat(bodyOf("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")).isEqualTo("hello")
        assertThat(
            bodyOf(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
                    "5;name=value\r\nhello\r\n6\r\n world\r\n0\r\nTrailer-Field: ignored\r\n\r\n",
            ),
        ).isEqualTo("hello world")
        assertThat(bodyOf("HTTP/1.0 200 OK\r\n\r\nread to the end")).isEqualTo("read to the end")
        assertThat(bodyOf("HTTP/1.1 200\r\ncontent-LENGTH: 0\r\n\r\n")).isEmpty()
        assertThat(bodyOf("HTTP/1.1 200 OK\nContent-Length: 2\n\nok")).isEqualTo("ok")
        assertThat(bodyOf("HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: 2\r\n\r\nok"))
            .isEqualTo("ok")
        assertThat(bodyOf("HTTP/1.1 200 OK\r\nContent-Length: $LIMIT\r\n\r\n" + "a".repeat(LIMIT))).hasSize(LIMIT)
    }

    @Test
    fun `interim responses are skipped`() {
        assertThat(
            bodyOf("HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
        ).isEqualTo("ok")
    }

    @Test
    fun `another status is returned without its body being read`() {
        val response = read("HTTP/1.1 404 Not Found\r\nContent-Length: 999999999\r\nTransfer-Encoding: x\r\n\r\n")
        assertThat(response.status).isEqualTo(404)
        assertThat(response.body).isNull()
    }

    @Test
    fun `a response it would have to guess how to read is refused`() {
        mapOf(
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello" to
                "the response has both Transfer-Encoding and Content-Length",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n" to
                "the response's Transfer-Encoding is not chunked",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n" to
                "the response's Transfer-Encoding is not chunked",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello" to "a malformed Content-Length",
            "HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nhello" to "a malformed Content-Length",
            "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n" to "a malformed Content-Length",
            "HTTP/1.1 200 OK\r\nContent-Length: 1234567890123456789\r\n\r\n" to "a malformed Content-Length",
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nok" to
                "the response is content-encoded, which the request did not accept",
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n" to
                "the server switched protocols, which the request did not ask for",
            "HTTP/1.1 100 Continue\r\n\r\n".repeat(5) + "HTTP/1.1 200 OK\r\n\r\n" to
                "no final response after 4 interim ones",
        ).forEach { (raw, why) -> assertRefused(raw, why) }
    }

    @Test
    fun `a malformed head is refused`() {
        mapOf(
            "" to "the server closed the connection unanswered",
            "SSH-2.0-OpenSSH_9.8\r\n\r\n" to "not an HTTP/1.x response",
            "HTTP/2 200\r\n\r\n" to "not an HTTP/1.x response",
            "HTTP/1.1 20 OK\r\n\r\n" to "not an HTTP/1.x response",
            "HTTP/1.1 200 OK\r\nFolded: a\r\n b\r\n\r\n" to "a header line without a name",
            "HTTP/1.1 200 OK\r\nno colon here\r\n\r\n" to "a header line without a name",
            "HTTP/1.1 200 OK\r\n: no name\r\n\r\n" to "a header line without a name",
            "HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n" to "a malformed header name",
            "HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\n" to "a bare CR in the response",
            "HTTP/1.1 200 OK\r\nX: " + "a".repeat(8 * 1024) + "\r\n\r\n" to "a response line longer than 8192 bytes",
            "HTTP/1.1 200 OK\r\n" + "X: ${"a".repeat(1000)}\r\n".repeat(70) + "\r\n" to
                "a response head longer than 65536 bytes",
            "HTTP/1.1 200 OK\r\nX: a\r\n" to "the response ended early",
            "HTTP/1.1 200 OK\r\nX: a" to "the response ended early",
        ).forEach { (raw, why) -> assertRefused(raw, why) }
    }

    @Test
    fun `a malformed body is refused`() {
        val chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        mapOf(
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort" to "the response ended early",
            "${chunked}zz\r\n" to "a malformed chunk size",
            "$chunked\r\n" to "a malformed chunk size",
            "${chunked}1234567890abcdef\r\n" to "a malformed chunk size",
            "${chunked}5\r\nhelloXX\r\n0\r\n\r\n" to "a chunk not followed by CRLF",
            "${chunked}5\r\nhel" to "the response ended early",
            "${chunked}5\r\nhello\r\n" to "the response ended early",
            "${chunked}0\r\n" to "the response ended early",
        ).forEach { (raw, why) -> assertRefused(raw, why) }
    }

    @Test
    fun `a body over the limit is refused, whatever frames it`() {
        val tooLong = "a".repeat(LIMIT + 1)
        listOf(
            "HTTP/1.1 200 OK\r\nContent-Length: ${LIMIT + 1}\r\n\r\n",
            "HTTP/1.1 200 OK\r\n\r\n$tooLong",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n${(LIMIT + 1).toString(16)}\r\n$tooLong\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
                "200\r\n${"a".repeat(512)}\r\n".repeat(2) + "1\r\na\r\n0\r\n\r\n",
        ).forEach { assertRefused(it, "response larger than $LIMIT bytes") }
    }

    private fun assertRefused(
        raw: String,
        why: String,
    ) {
        assertThatThrownBy { read(raw) }
            .describedAs(raw.take(80))
            .isInstanceOf(IOException::class.java)
            .hasMessage(why)
    }

    private companion object {
        const val LIMIT = 1024
    }
}
