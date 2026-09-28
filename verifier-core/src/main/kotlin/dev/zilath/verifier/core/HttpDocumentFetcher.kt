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

import java.io.IOException
import java.io.InterruptedIOException
import java.net.InetAddress
import java.net.URI
import java.net.http.HttpTimeoutException
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory

/**
 * A [StatusListFetcher] that holds the network boundary the fetcher contracts leave to their
 * implementation, over the JDK's sockets and TLS. `HttpFederationFetcher`, in
 * `verifier-trust-itwallet`, puts the same boundary in front of a federation's documents.
 *
 * Before anything is sent, the URL must pass the library's shape rule
 * ([usableHttpsUriOrNull]) and its host must resolve only to globally routable addresses:
 * a single private, loopback or link-local address among them — link-local is where cloud
 * metadata services answer — and the fetch is refused. [destinations] can admit loopback as
 * well, for a federation or a status list served on the same machine in development, or admit
 * loopback alone; see [Destinations].
 *
 * The connection then goes to one of the addresses that were checked, and to nothing else:
 * the name is resolved once, so a resolver that changes its answer between the check and the
 * connection (DNS rebinding) has nothing to change. Over https the TLS session is still opened
 * for the name — its SNI, and the certificate verified against it.
 *
 * The request is one HTTP/1.1 GET of at most 8 KiB, and no redirect is followed: a redirect is
 * a failure. The connection must be made within [connectTimeout], and the whole fetch — the
 * name lookup, the connection, the response — must complete within [totalTimeout]; a body
 * longer than [maxResponseBytes] is refused as it arrives, before it is held whole. Only a 200 is a
 * document: 404 and 410 throw [DocumentNotFoundException], the server's answer that there is
 * no such document, and anything else throws an [IOException], as does a response this
 * fetcher would have to guess how to read.
 *
 * A lookup is not stopped when its fetch gives up on it: one that does not answer keeps its
 * thread until the resolver returns, whatever the fetch's deadline. So each fetcher runs at most
 * [MAX_CONCURRENT_LOOKUPS] of them at once, and a fetch that finds them all taken is refused
 * rather than queued behind lookups that have outlived their fetches.
 *
 * It connects directly and uses none of the JVM's proxy settings: a deployment that must
 * reach the internet through a proxy needs a fetcher of its own, and then the proxy's rules
 * are the boundary.
 *
 * [sslContext] replaces the JVM's default TLS trust, for a deployment whose documents are
 * served under a private CA.
 */
class HttpDocumentFetcher internal constructor(
    private val connectTimeout: Duration,
    private val totalTimeout: Duration,
    private val maxResponseBytes: Int,
    private val destinations: Destinations,
    sslContext: SSLContext?,
    private val resolve: (String) -> List<InetAddress>,
) : StatusListFetcher {
    /**
     * A fetcher with the given bounds: by default [DEFAULT_CONNECT_TIMEOUT],
     * [DEFAULT_TOTAL_TIMEOUT], [DEFAULT_MAX_RESPONSE_BYTES], [Destinations.PUBLIC] and the
     * JVM's TLS trust.
     */
    constructor(
        connectTimeout: Duration = DEFAULT_CONNECT_TIMEOUT,
        totalTimeout: Duration = DEFAULT_TOTAL_TIMEOUT,
        maxResponseBytes: Int = DEFAULT_MAX_RESPONSE_BYTES,
        destinations: Destinations = Destinations.PUBLIC,
        sslContext: SSLContext? = null,
    ) : this(connectTimeout, totalTimeout, maxResponseBytes, destinations, sslContext, ::resolveAll)

    /** The addresses a fetch may connect to; the name of the URL must resolve only to these. */
    enum class Destinations {
        /** Globally routable addresses only: the default, and the setting for production. */
        PUBLIC,

        /**
         * Loopback as well, for documents served on the same machine in development. A process
         * that shares its host with services of its own should not use it.
         */
        PUBLIC_AND_LOOPBACK,

        /**
         * Loopback only, for a federation that runs entirely on this machine — and the one
         * setting under which an `sslContext` that trusts every certificate still reaches
         * nothing beyond it.
         */
        LOOPBACK,
    }

    init {
        require(connectTimeout > Duration.ZERO) { "connectTimeout must be positive" }
        require(totalTimeout > Duration.ZERO) { "totalTimeout must be positive" }
        require(maxResponseBytes > 0) { "maxResponseBytes must be positive" }
    }

    private val tls: SSLSocketFactory = (sslContext ?: SSLContext.getDefault()).socketFactory

    private val lookups =
        ThreadPoolExecutor(
            0,
            MAX_CONCURRENT_LOOKUPS,
            LOOKUP_THREAD_IDLE_SECONDS,
            TimeUnit.SECONDS,
            SynchronousQueue(),
            ThreadFactory { task -> Thread(task, "zilath-name-lookup").apply { isDaemon = true } },
        )

    /**
     * The body served at [uri], decoded as UTF-8. Throws [DocumentNotFoundException] on a 404
     * or a 410, and an [IOException] on any other failure — a refused destination among them.
     */
    @OptIn(InternalZilathApi::class)
    override fun fetch(uri: String): String {
        val deadline = FetchDeadline(totalTimeout)
        val target = usableHttpsUriOrNull(uri) ?: throw IOException("refused: not a URL this fetcher dereferences")
        val pinned = PinnedTarget(target, acceptedAddresses(target, deadline))
        val response = pinnedGet(pinned, tls, connectTimeout, deadline, maxResponseBytes)
        return when (val status = response.status) {
            HTTP_OK -> String(response.body ?: ByteArray(0), Charsets.UTF_8)
            HTTP_NOT_FOUND, HTTP_GONE -> throw DocumentNotFoundException("the server answered $status")
            else -> throw IOException("the server answered $status")
        }
    }

    /** The addresses [target]'s host resolves to, once every one of them may be reached. */
    @OptIn(InternalZilathApi::class)
    private fun acceptedAddresses(
        target: URI,
        deadline: FetchDeadline,
    ): List<InetAddress> {
        val host = target.host.removeSurrounding("[", "]")
        val addresses = lookUp(host, deadline)
        if (addresses.isEmpty() || !addresses.all { isReachableDestination(it, destinations) }) {
            throw IOException("refused: ${boundedPrintable(host)} resolves to an address this fetcher does not reach")
        }
        return addresses
    }

    /** The addresses [host] resolves to, looked up on [lookups] and within [deadline]. */
    private fun lookUp(
        host: String,
        deadline: FetchDeadline,
    ): List<InetAddress> {
        val lookup =
            try {
                CompletableFuture.supplyAsync({ resolve(host) }, lookups)
            } catch (busy: RejectedExecutionException) {
                throw IOException("refused: $MAX_CONCURRENT_LOOKUPS name lookups already in progress", busy)
            }
        return awaitWithin(lookup, deadline.remaining(), "the name lookup")
    }

    companion object {
        /** Five seconds to connect: the documents come from hosts the credential names. */
        val DEFAULT_CONNECT_TIMEOUT: Duration = Duration.ofSeconds(5)

        /** Ten seconds for the whole response, so that a slow host cannot stall a checkout. */
        val DEFAULT_TOTAL_TIMEOUT: Duration = Duration.ofSeconds(10)

        /**
         * One mebibyte. The production IT-Wallet federation documents in the test fixtures,
         * as served on 2026-09-24, run from 4 to 40 KB; a status list travels compressed, and
         * one bit per credential for a million credentials is 125 KB before compression.
         */
        const val DEFAULT_MAX_RESPONSE_BYTES: Int = 1 shl 20

        /** How many name lookups one fetcher runs at once; see the class documentation. */
        const val MAX_CONCURRENT_LOOKUPS: Int = 16

        private const val LOOKUP_THREAD_IDLE_SECONDS = 30L
    }
}

/** Thrown by [HttpDocumentFetcher] when the server answers that there is no such document. */
class DocumentNotFoundException(
    message: String,
) : IOException(message)

private fun resolveAll(host: String): List<InetAddress> = InetAddress.getAllByName(host).toList()

/**
 * The result of [work] — [what], for the messages — within [timeout], or an [IOException];
 * on failure [work] is cancelled.
 */
private fun <T> awaitWithin(
    work: CompletableFuture<T>,
    timeout: Duration,
    what: String,
): T {
    val failure: IOException =
        try {
            return work.get(timeout.toNanos(), TimeUnit.NANOSECONDS)
        } catch (late: TimeoutException) {
            HttpTimeoutException("$what did not complete within $timeout").apply { initCause(late) }
        } catch (failed: ExecutionException) {
            failed.cause as? IOException ?: IOException("$what failed", failed.cause)
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            InterruptedIOException("interrupted while waiting for $what").apply { initCause(interrupted) }
        }
    work.cancel(true)
    throw failure
}

private const val HTTP_OK = 200
private const val HTTP_NOT_FOUND = 404
private const val HTTP_GONE = 410
