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

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.Locale

/** A response as far as a fetch needs it: its status, and a 200's body. */
internal class PinnedResponse(
    val status: Int,
    val body: ByteArray?,
)

/**
 * Reads one HTTP/1.1 response (RFC 9112) from [input], and only as much of it as a fetch of a
 * document needs: the status line and header fields, and a 200's body, of at most
 * [maxBodyBytes], framed by `Transfer-Encoding: chunked`, by `Content-Length` or by the end of
 * the connection. Interim 1xx responses are skipped.
 *
 * Every line is bounded, and the head as a whole. What it would have to guess at, it refuses:
 * `Transfer-Encoding` together with `Content-Length`, a coding other than `chunked`, more than
 * one or a malformed `Content-Length`, a malformed chunk, a folded header line, a bare CR, a
 * response that ends early, a content coding the request did not accept, a switch of
 * protocols nobody asked for. Every refusal is an [IOException]. What a response carries is
 * then verified as a signed document; a parsing mistake here can fail a fetch, not make a
 * document believed.
 */
internal class Http1ResponseReader(
    private val input: InputStream,
    private val maxBodyBytes: Int,
) {
    /** Bytes of status lines, header fields and trailers read so far. */
    private var headBytes = 0

    /** The final response: its status, and the body when that status is 200. */
    fun read(): PinnedResponse {
        var head = readHead()
        var interim = 0
        while (head.status in INFORMATIONAL && head.status != SWITCHING_PROTOCOLS && interim < MAX_INTERIM) {
            interim++
            head = readHead()
        }
        return when (head.status) {
            SWITCHING_PROTOCOLS -> malformed("the server switched protocols, which the request did not ask for")
            in INFORMATIONAL -> malformed("no final response after $interim interim ones")
            HTTP_OK -> PinnedResponse(HTTP_OK, readBody(head))
            else -> PinnedResponse(head.status, null)
        }
    }

    private fun readHead(): Head {
        val statusLine = readLine(countsTowardsHead = true) ?: malformed("the server closed the connection unanswered")
        val status =
            STATUS_LINE
                .matchEntire(statusLine)
                ?.groupValues
                ?.get(1)
                ?.toInt() ?: malformed("not an HTTP/1.x response")
        return Head(status, readFields())
    }

    /** Header fields, or trailer fields, up to the empty line; names lowercased. */
    private fun readFields(): Map<String, List<String>> {
        val fields = mutableMapOf<String, MutableList<String>>()
        var line = readLine(countsTowardsHead = true) ?: malformed("the response ended early")
        while (line.isNotEmpty()) {
            val (name, value) = fieldOf(line)
            fields.getOrPut(name) { mutableListOf() } += value
            line = readLine(countsTowardsHead = true) ?: malformed("the response ended early")
        }
        return fields
    }

    private fun readBody(head: Head): ByteArray {
        if (head.values("content-encoding").any { !it.equals("identity", ignoreCase = true) }) {
            malformed("the response is content-encoded, which the request did not accept")
        }
        val transfer = head.values("transfer-encoding")
        val length = head.values("content-length")
        return when {
            transfer.isNotEmpty() && length.isNotEmpty() ->
                malformed("the response has both Transfer-Encoding and Content-Length")
            transfer.isNotEmpty() ->
                if (transfer.singleOrNull().equals("chunked", ignoreCase = true)) {
                    readChunked()
                } else {
                    malformed("the response's Transfer-Encoding is not chunked")
                }
            length.isNotEmpty() -> readExactly(declaredLength(length))
            else -> readToEnd()
        }
    }

    private fun declaredLength(values: List<String>): Int {
        val length = values.singleOrNull()?.takeIf(DIGITS::matches)?.toLong() ?: malformed("a malformed Content-Length")
        if (length > maxBodyBytes) tooLarge(maxBodyBytes)
        return length.toInt()
    }

    private fun readChunked(): ByteArray {
        val body = ByteArrayOutputStream()
        var size = chunkSizeOf(readLine(countsTowardsHead = false) ?: malformed("the response ended early"))
        while (size > 0) {
            if (body.size() + size > maxBodyBytes) tooLarge(maxBodyBytes)
            body.writeBytes(readExactly(size.toInt()))
            if (readLine(countsTowardsHead = false) != "") malformed("a chunk not followed by CRLF")
            size = chunkSizeOf(readLine(countsTowardsHead = false) ?: malformed("the response ended early"))
        }
        // Trailer fields, which carry nothing a document needs.
        readFields()
        return body.toByteArray()
    }

    private fun readExactly(count: Int): ByteArray {
        val bytes = ByteArray(count)
        var read = 0
        while (read < count) {
            val chunk = input.read(bytes, read, count - read)
            if (chunk == -1) malformed("the response ended early")
            read += chunk
        }
        return bytes
    }

    private fun readToEnd(): ByteArray {
        val body = ByteArrayOutputStream()
        val buffer = ByteArray(READ_BUFFER_BYTES)
        var chunk = input.read(buffer)
        while (chunk != -1) {
            if (body.size() + chunk > maxBodyBytes) tooLarge(maxBodyBytes)
            body.write(buffer, 0, chunk)
            chunk = input.read(buffer)
        }
        return body.toByteArray()
    }

    /**
     * One line, without its line ending, or null when the input ended before it began. CRLF
     * ends a line, and so does a bare LF (RFC 9112 §2.2); a CR anywhere else is refused.
     */
    private fun readLine(countsTowardsHead: Boolean): String? {
        var byte = input.read()
        val line = ByteArrayOutputStream()
        while (byte != LF && byte != -1) {
            line.write(byte)
            if (line.size() > MAX_LINE_BYTES) malformed("a response line longer than $MAX_LINE_BYTES bytes")
            byte = input.read()
        }
        if (byte == -1 && line.size() > 0) malformed("the response ended early")
        if (countsTowardsHead) headBytes += line.size() + 1
        if (headBytes > MAX_HEAD_BYTES) malformed("a response head longer than $MAX_HEAD_BYTES bytes")
        val text = line.toString(Charsets.ISO_8859_1).removeSuffix("\r")
        if ('\r' in text) malformed("a bare CR in the response")
        return text.takeUnless { byte == -1 }
    }

    private class Head(
        val status: Int,
        private val fields: Map<String, List<String>>,
    ) {
        fun values(name: String): List<String> = fields[name].orEmpty()
    }
}

/** [line] as a field name, lowercased, and its value; a folded line or a missing name is refused. */
private fun fieldOf(line: String): Pair<String, String> {
    val colon = line.indexOf(':')
    // A continuation line begins with whitespace, which no field name contains: obs-fold,
    // which RFC 9112 §5.2 lets a client refuse, fails here with every other malformed name.
    val name = if (colon > 0) line.substring(0, colon) else malformed("a header line without a name")
    if (!FIELD_NAME.matches(name)) malformed("a malformed header name")
    return name.lowercase(Locale.ROOT) to line.substring(colon + 1).trim(' ', '\t')
}

/** The size in a chunk-size line, its extensions ignored. */
private fun chunkSizeOf(line: String): Long =
    line
        .substringBefore(';')
        .trim(' ', '\t')
        .takeIf(HEX_DIGITS::matches)
        ?.toLong(HEX_RADIX) ?: malformed("a malformed chunk size")

private fun malformed(what: String): Nothing = throw IOException(what)

private fun tooLarge(limit: Int): Nothing = throw IOException("response larger than $limit bytes")

private val STATUS_LINE = Regex("""HTTP/1\.[01] ([0-9]{3})(?: .*)?""")

/** RFC 9110 §5.6.2: a token. */
private val FIELD_NAME = Regex("""[!#$%&'*+\-.^_`|~0-9A-Za-z]+""")

/** Up to 18 digits: whatever they say fits in a Long. */
private val DIGITS = Regex("""[0-9]{1,18}""")

/** Up to 15 hex digits, for the same reason. */
private val HEX_DIGITS = Regex("""[0-9A-Fa-f]{1,15}""")

private val INFORMATIONAL = IntRange(FIRST_INFORMATIONAL, LAST_INFORMATIONAL)
private const val FIRST_INFORMATIONAL = 100
private const val LAST_INFORMATIONAL = 199
private const val SWITCHING_PROTOCOLS = 101
private const val HTTP_OK = 200
private const val MAX_INTERIM = 4
private const val MAX_LINE_BYTES = 8 * 1024
private const val MAX_HEAD_BYTES = 64 * 1024
private const val READ_BUFFER_BYTES = 8 * 1024
private const val HEX_RADIX = 16
private const val LF = '\n'.code
