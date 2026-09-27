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

import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URI
import java.net.http.HttpTimeoutException
import java.time.Duration
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Where a GET goes: [target], and the [addresses] its host was checked to resolve to. */
internal class PinnedTarget(
    val target: URI,
    val addresses: List<InetAddress>,
)

/**
 * One GET of [pinned]'s URL over HTTP/1.1, connected to one of its addresses and to nothing
 * else: the name is never resolved again, so the connection goes where the addresses were
 * checked to lead. Over https the TLS session is opened for the name in the URL — its SNI,
 * and the certificate verified against it — with [tls]. Every read runs against [deadline];
 * the body of a 200 is read within [maxBodyBytes], and any other status's is not read at all.
 */
internal fun pinnedGet(
    pinned: PinnedTarget,
    tls: SSLSocketFactory,
    connectTimeout: Duration,
    deadline: FetchDeadline,
    maxBodyBytes: Int,
): PinnedResponse =
    connect(pinned, tls, connectTimeout, deadline).use { socket ->
        socket.getOutputStream().apply {
            write(requestFor(pinned.target))
            flush()
        }
        Http1ResponseReader(BufferedInputStream(DeadlineInput(socket, deadline)), maxBodyBytes).read()
    }

/** The request: a GET that asks for the body as it is, and for the connection to close after. */
private fun requestFor(target: URI): ByteArray {
    val requestTarget = (target.rawPath?.ifEmpty { null } ?: "/") + (target.rawQuery?.let { "?$it" } ?: "")
    val host = if (target.port == -1) target.host else "${target.host}:${target.port}"
    // java.net.URI refuses whitespace and control characters, so none can reach the request
    // line; the check keeps that true whatever produced the URI.
    if ("$requestTarget$host".any { it.isWhitespace() || it.isISOControl() }) {
        throw IOException("refused: the URL cannot be written into a request")
    }
    return (
        "GET $requestTarget HTTP/1.1\r\n" +
            "Host: $host\r\n" +
            "Accept-Encoding: identity\r\n" +
            "Connection: close\r\n" +
            "\r\n"
    ).toByteArray(Charsets.US_ASCII)
}

/**
 * A socket to the first of [pinned]'s addresses that accepts within [connectTimeout] — and
 * within [deadline] — with TLS on it when the URL is https.
 */
private fun connect(
    pinned: PinnedTarget,
    tls: SSLSocketFactory,
    connectTimeout: Duration,
    deadline: FetchDeadline,
): Socket {
    val target = pinned.target
    val port =
        when {
            target.port != -1 -> target.port
            target.scheme == "https" -> HTTPS_PORT
            else -> HTTP_PORT
        }
    var failure: IOException? = null
    for (address in pinned.addresses) {
        val timeout =
            minOf(connectTimeout.toMillis(), deadline.remaining().toMillis())
                .coerceIn(1L, Int.MAX_VALUE.toLong())
                .toInt()
        // Proxy.NO_PROXY: a SOCKS proxy the JVM is configured with would otherwise carry it.
        val socket = Socket(Proxy.NO_PROXY)
        try {
            socket.connect(InetSocketAddress(address, port), timeout)
            return if (target.scheme == "https") secured(socket, target, port, tls, deadline) else socket
        } catch (refused: IOException) {
            socket.close()
            failure?.addSuppressed(refused) ?: run { failure = refused }
        }
    }
    throw failure ?: IOException("no address to connect to")
}

/** [plain] under TLS for the name in [target], the certificate verified against that name. */
private fun secured(
    plain: Socket,
    target: URI,
    port: Int,
    tls: SSLSocketFactory,
    deadline: FetchDeadline,
): Socket {
    val secure = tls.createSocket(plain, target.host.removeSurrounding("[", "]"), port, true) as SSLSocket
    secure.sslParameters = secure.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
    secure.soTimeout = deadline.remainingMillis()
    secure.startHandshake()
    return secure
}

/** The socket's input, each read bounded by what is left of [deadline]. */
private class DeadlineInput(
    private val socket: Socket,
    private val deadline: FetchDeadline,
) : InputStream() {
    private val input = socket.getInputStream()

    override fun read(): Int = timed { input.read() }

    override fun read(
        buffer: ByteArray,
        offset: Int,
        length: Int,
    ): Int = timed { input.read(buffer, offset, length) }

    private inline fun timed(read: () -> Int): Int {
        socket.soTimeout = deadline.remainingMillis()
        return try {
            read()
        } catch (late: SocketTimeoutException) {
            throw HttpTimeoutException("the response did not complete in time").apply { initCause(late) }
        }
    }
}

private const val HTTP_PORT = 80
private const val HTTPS_PORT = 443
