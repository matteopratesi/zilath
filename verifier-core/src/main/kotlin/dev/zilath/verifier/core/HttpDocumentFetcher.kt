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
import java.io.InterruptedIOException
import java.net.InetAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.http.HttpTimeoutException
import java.nio.ByteBuffer
import java.time.Duration
import java.util.OptionalLong
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionStage
import java.util.concurrent.ExecutionException
import java.util.concurrent.Flow
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import javax.net.ssl.SSLContext

/**
 * A [StatusListFetcher] over the JDK's HTTP client that holds the network boundary the
 * fetcher contracts leave to their implementation. `HttpFederationFetcher`, in
 * `verifier-trust-itwallet`, puts the same boundary in front of a federation's documents.
 *
 * Before anything is sent, the URL must pass the library's shape rule
 * ([usableHttpsUriOrNull]) and its host must resolve only to globally routable addresses:
 * a single private, loopback or link-local address among them — link-local is where cloud
 * metadata services answer — and the fetch is refused. [allowLoopback] admits loopback, for
 * a federation or a status list served on the same machine in development; a process that
 * shares its host with services of its own should not set it.
 *
 * Then no redirect is followed: a redirect is a failure. The connection must be made within
 * [connectTimeout], and the whole fetch — the name lookup, the connection, the response —
 * must complete within [totalTimeout]; a body longer than [maxResponseBytes] is refused as it
 * arrives, before it is held whole. Only a 200 is a document: 404 and 410 throw
 * [DocumentNotFoundException], the server's answer that there is no such document, and
 * anything else throws an [IOException].
 *
 * A lookup is not stopped when its fetch gives up on it: one that does not answer keeps its
 * thread until the resolver returns, whatever the fetch's deadline. So each fetcher runs at most
 * [MAX_CONCURRENT_LOOKUPS] of them at once, and a fetch that finds them all taken is refused
 * rather than queued behind lookups that have outlived their fetches.
 *
 * What this does NOT close: the name is resolved twice, once here to check it and once by
 * the HTTP client to connect, and a resolver that changes its answer in between (DNS
 * rebinding) can still lead the connection elsewhere. Where the deployment has an internal
 * network to protect, an egress rule at the network boundary is what closes that. Through a
 * proxy the JVM is set up to use, the proxy resolves the name again, and its rules decide.
 *
 * [sslContext] replaces the JVM's default TLS trust, for a deployment whose documents are
 * served under a private CA.
 */
class HttpDocumentFetcher internal constructor(
    private val connectTimeout: Duration,
    private val totalTimeout: Duration,
    private val maxResponseBytes: Int,
    private val allowLoopback: Boolean,
    sslContext: SSLContext?,
    private val resolve: (String) -> List<InetAddress>,
) : StatusListFetcher {
    /**
     * A fetcher with the given bounds: by default [DEFAULT_CONNECT_TIMEOUT],
     * [DEFAULT_TOTAL_TIMEOUT], [DEFAULT_MAX_RESPONSE_BYTES], loopback refused and the JVM's
     * TLS trust.
     */
    constructor(
        connectTimeout: Duration = DEFAULT_CONNECT_TIMEOUT,
        totalTimeout: Duration = DEFAULT_TOTAL_TIMEOUT,
        maxResponseBytes: Int = DEFAULT_MAX_RESPONSE_BYTES,
        allowLoopback: Boolean = false,
        sslContext: SSLContext? = null,
    ) : this(connectTimeout, totalTimeout, maxResponseBytes, allowLoopback, sslContext, ::resolveAll)

    init {
        require(connectTimeout > Duration.ZERO) { "connectTimeout must be positive" }
        require(totalTimeout > Duration.ZERO) { "totalTimeout must be positive" }
        require(maxResponseBytes > 0) { "maxResponseBytes must be positive" }
    }

    private val lookups =
        ThreadPoolExecutor(
            0,
            MAX_CONCURRENT_LOOKUPS,
            LOOKUP_THREAD_IDLE_SECONDS,
            TimeUnit.SECONDS,
            SynchronousQueue(),
            ThreadFactory { task -> Thread(task, "zilath-name-lookup").apply { isDaemon = true } },
        )

    private val client: HttpClient =
        HttpClient
            .newBuilder()
            .connectTimeout(connectTimeout)
            .followRedirects(HttpClient.Redirect.NEVER)
            .apply { if (sslContext != null) sslContext(sslContext) }
            .build()

    /**
     * The body served at [uri], decoded as UTF-8. Throws [DocumentNotFoundException] on a 404
     * or a 410, and an [IOException] on any other failure — a refused destination among them.
     */
    override fun fetch(uri: String): String {
        val deadline = System.nanoTime() + totalTimeout.toNanos()
        val target = acceptedTarget(uri, deadline)
        val remaining = remainingUntil(deadline)
        val request =
            HttpRequest
                .newBuilder(target)
                .timeout(remaining)
                .GET()
                .build()
        val response = awaitWithin(client.sendAsync(request, ::bodyFor), remaining, "the response")
        return when (val status = response.statusCode()) {
            HTTP_OK -> String(response.body() ?: ByteArray(0), Charsets.UTF_8)
            HTTP_NOT_FOUND, HTTP_GONE -> throw DocumentNotFoundException("the server answered $status")
            else -> throw IOException("the server answered $status")
        }
    }

    /** [uri] once its shape passes and every address its host resolves to may be reached. */
    @OptIn(InternalZilathApi::class)
    private fun acceptedTarget(
        uri: String,
        deadline: Long,
    ): URI {
        val target = usableHttpsUriOrNull(uri) ?: throw IOException("refused: not a URL this fetcher dereferences")
        val host = target.host.removeSurrounding("[", "]")
        val addresses = lookUp(host, deadline)
        if (addresses.isEmpty() || !addresses.all { isReachableDestination(it, allowLoopback) }) {
            throw IOException("refused: ${boundedPrintable(host)} resolves to an address this fetcher does not reach")
        }
        return target
    }

    /** The addresses [host] resolves to, looked up on [lookups] and within [deadline]. */
    private fun lookUp(
        host: String,
        deadline: Long,
    ): List<InetAddress> {
        val lookup =
            try {
                CompletableFuture.supplyAsync({ resolve(host) }, lookups)
            } catch (busy: RejectedExecutionException) {
                throw IOException("refused: $MAX_CONCURRENT_LOOKUPS name lookups already in progress", busy)
            }
        return awaitWithin(lookup, remainingUntil(deadline), "the name lookup")
    }

    /** What is left of the fetch's time until [deadline]; a timeout once nothing is. */
    private fun remainingUntil(deadline: Long): Duration {
        val left = deadline - System.nanoTime()
        if (left <= 0) throw HttpTimeoutException("the fetch did not complete within $totalTimeout")
        return Duration.ofNanos(left)
    }

    /** A 200's body, bounded; any other status's body is read and dropped. */
    private fun bodyFor(info: HttpResponse.ResponseInfo): HttpResponse.BodySubscriber<ByteArray?> =
        if (info.statusCode() == HTTP_OK) {
            BoundedBody(maxResponseBytes, info.headers().firstValueAsLong("content-length"))
        } else {
            HttpResponse.BodySubscribers.replacing(null)
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
 * on failure [work] is cancelled, so that nothing keeps reading from the server.
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

/**
 * Collects a body of at most [limit] bytes, refusing it as soon as it — or the length its
 * headers declare — goes past that, instead of after holding it whole.
 */
private class BoundedBody(
    private val limit: Int,
    declaredLength: OptionalLong,
) : HttpResponse.BodySubscriber<ByteArray?> {
    private val body = CompletableFuture<ByteArray?>()
    private val collected = ByteArrayOutputStream()
    private val declaredTooLong = declaredLength.isPresent && declaredLength.asLong > limit
    private lateinit var subscription: Flow.Subscription

    override fun getBody(): CompletionStage<ByteArray?> = body

    override fun onSubscribe(subscription: Flow.Subscription) {
        this.subscription = subscription
        if (declaredTooLong) refuse() else subscription.request(Long.MAX_VALUE)
    }

    override fun onNext(item: List<ByteBuffer>) {
        val incoming = item.sumOf { it.remaining().toLong() }
        when {
            body.isDone -> Unit
            collected.size() + incoming > limit -> refuse()
            else -> item.forEach { buffer -> collected.writeBytes(buffer.toByteArray()) }
        }
    }

    override fun onError(throwable: Throwable) {
        body.completeExceptionally(throwable)
    }

    override fun onComplete() {
        body.complete(collected.toByteArray())
    }

    private fun refuse() {
        subscription.cancel()
        body.completeExceptionally(IOException("response larger than $limit bytes"))
    }
}

private fun ByteBuffer.toByteArray(): ByteArray = ByteArray(remaining()).also { get(it) }

private const val HTTP_OK = 200
private const val HTTP_NOT_FOUND = 404
private const val HTTP_GONE = 410
