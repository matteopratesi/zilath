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

import dev.zilath.verifier.openid4vp.FlowOutcome
import dev.zilath.verifier.openid4vp.PresentationRequest
import dev.zilath.verifier.openid4vp.RelyingPartyConfiguration
import dev.zilath.verifier.openid4vp.RpEntityConfiguration
import dev.zilath.verifier.openid4vp.TransactionId
import dev.zilath.verifier.openid4vp.VerificationFlow
import dev.zilath.verifier.trust.FederationFetcher
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RestController
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Clock
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/** Starts transactions and exposes outcomes so the conformance tool can drive the flow. */
@RestController
class ConformanceController(
    private val flow: VerificationFlow,
    private val config: RelyingPartyConfiguration,
    private val clock: Clock,
    @Value("\${zilath.demo.pid-vct:urn:eu.europa.ec.eudi:pid:1}") private val pidVct: String,
) {
    /** The RP entity configuration (VARCO-33): how a federation discovers and onboards us. */
    @GetMapping("/.well-known/openid-federation")
    fun entityConfiguration(): ResponseEntity<String> {
        val federation =
            config.federation
                ?: return ResponseEntity.notFound().build()
        return ResponseEntity
            .ok()
            .contentType(MediaType.parseMediaType(RpEntityConfiguration.MEDIA_TYPE))
            .body(RpEntityConfiguration.build(config, federation, clock))
    }

    @GetMapping("/conformance/start")
    fun start(): Map<String, String> {
        // The conformance wallet POSTs the response and then expects to be handed a
        // redirect back: that IS the same-device flow, whatever the QR suggests.
        val started =
            flow.start(PresentationRequest.forTestPid(pidVct), dev.zilath.verifier.openid4vp.FlowMode.SAME_DEVICE)
        return mapOf(
            "transactionId" to started.id.value,
            "authorizeUrl" to started.qrPayload,
            "requestUri" to started.requestUri,
        )
    }

    /**
     * What the conformance harness polls: whether the run succeeded, and why not if it did
     * not. The CATEGORY only.
     *
     * This used to be `awaitOutcome(...).toString()`, and the data class it stringified
     * carries the disclosed claims — so an unauthenticated GET with a transaction id
     * returned somebody's name and entitlement. The harness never needed them, and neither
     * does anything else: an outcome is a yes or a no.
     */
    @GetMapping("/conformance/outcome/{txId}")
    fun outcome(
        @PathVariable txId: String,
    ): Map<String, String> =
        when (val outcome = flow.awaitOutcome(TransactionId(txId))) {
            is FlowOutcome.Verified -> mapOf("outcome" to "verified")
            is FlowOutcome.Rejected -> mapOf("outcome" to "rejected", "reason" to outcome.reason.name)
            is FlowOutcome.WalletErrorAcknowledged -> mapOf("outcome" to "wallet_error")
            FlowOutcome.Pending -> mapOf("outcome" to "pending")
            FlowOutcome.Expired -> mapOf("outcome" to "expired")
            FlowOutcome.Unknown -> mapOf("outcome" to "unknown")
        }
}

/**
 * Federation fetcher over the JDK HTTP client. With [insecureTls] the TLS trust checks
 * are DISABLED: acceptable only against the conformance tool's local, self-signed
 * trust anchor server on localhost — never against anything reachable from outside.
 */
internal fun httpFetcher(insecureTls: Boolean): FederationFetcher {
    val builder = HttpClient.newBuilder()
    if (insecureTls) {
        val trustAll =
            object : X509TrustManager {
                override fun checkClientTrusted(
                    chain: Array<X509Certificate>,
                    authType: String,
                ) = Unit

                override fun checkServerTrusted(
                    chain: Array<X509Certificate>,
                    authType: String,
                ) = Unit

                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
        val context = SSLContext.getInstance("TLS")
        context.init(null, arrayOf(trustAll), SecureRandom())
        builder.sslContext(context)
    }
    val client = builder.connectTimeout(java.time.Duration.ofSeconds(CONNECT_TIMEOUT_SECONDS)).build()
    return FederationFetcher { url ->
        val uri = URI.create(url)
        if (insecureTls) {
            // The documented restriction, enforced: trust-all TLS never leaves this machine.
            check(uri.host in LOOPBACK_HOSTS) { "insecure TLS is restricted to loopback, refused for ${uri.host}" }
        }
        val request =
            HttpRequest
                .newBuilder(uri)
                .timeout(java.time.Duration.ofSeconds(REQUEST_TIMEOUT_SECONDS))
                .GET()
                .build()
        val response = client.send(request, HttpResponse.BodyHandlers.ofString())
        check(response.statusCode() in HTTP_OK_MIN..HTTP_OK_MAX) { "GET $url returned ${response.statusCode()}" }
        check(
            response.body().length <= MAX_RESPONSE_CHARS,
        ) { "response from $url larger than $MAX_RESPONSE_CHARS chars" }
        response.body()
    }
}

private const val HTTP_OK_MIN = 200
private const val HTTP_OK_MAX = 299
private const val CONNECT_TIMEOUT_SECONDS = 5L
private const val REQUEST_TIMEOUT_SECONDS = 10L
private const val MAX_RESPONSE_CHARS = 256 * 1024
private val LOOPBACK_HOSTS = setOf("localhost", "127.0.0.1", "::1", "[::1]")
