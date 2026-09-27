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

import dev.zilath.verifier.core.HttpDocumentFetcher
import dev.zilath.verifier.openid4vp.FlowOutcome
import dev.zilath.verifier.openid4vp.PollToken
import dev.zilath.verifier.openid4vp.PresentationRequest
import dev.zilath.verifier.openid4vp.RelyingPartyConfiguration
import dev.zilath.verifier.openid4vp.RpEntityConfiguration
import dev.zilath.verifier.openid4vp.TransactionId
import dev.zilath.verifier.openid4vp.VerificationFlow
import dev.zilath.verifier.trust.FederationFetcher
import dev.zilath.verifier.trust.HttpFederationFetcher
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RestController
import java.net.URI
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
    /** The RP entity configuration: how a federation discovers and onboards us. */
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

    /**
     * Starts a same-device transaction for the conformance tool and returns its id, the
     * authorize URL, the request URI and the poll token that reads it until the return.
     */
    @GetMapping("/conformance/start")
    fun start(): Map<String, String> {
        // The conformance wallet POSTs the response and then expects to be handed a
        // redirect back: that IS the same-device flow, whatever the QR suggests.
        // Not registered with the demo pages, which answer only the browser that started a
        // purchase there: /demo/cb completes its return all the same, since the flow checks
        // the code, and hands the returning user-agent the token that reads the outcome.
        val started =
            flow.start(PresentationRequest.forTestPid(pidVct), dev.zilath.verifier.openid4vp.FlowMode.SAME_DEVICE)
        return mapOf(
            "transactionId" to started.id.value,
            "authorizeUrl" to started.qrPayload,
            "requestUri" to started.requestUri,
            // What reads the outcome below: the transaction id alone no longer does.
            "pollToken" to started.pollToken.value,
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
     *
     * Same-device, the start token reads pending until the user-agent comes back through
     * /demo/cb, and nothing afterwards: the flow hands the read right to the user-agent that
     * returned (OpenID4VP 1.0 §14.2), and /demo/cb gives it the token that reads from then
     * on. Even the category says something about the person whose wallet answered, so it is
     * not read back through the start token.
     */
    @GetMapping("/conformance/outcome/{txId}")
    fun outcome(
        @PathVariable txId: String,
        @org.springframework.web.bind.annotation.RequestParam pollToken: String,
    ): Map<String, String> =
        when (val outcome = flow.awaitOutcome(TransactionId(txId), PollToken(pollToken))) {
            is FlowOutcome.Verified -> mapOf("outcome" to "verified")
            is FlowOutcome.Rejected -> mapOf("outcome" to "rejected", "reason" to outcome.reason.name)
            is FlowOutcome.WalletErrorAcknowledged -> mapOf("outcome" to "wallet_error")
            FlowOutcome.Pending -> mapOf("outcome" to "pending")
            FlowOutcome.Expired -> mapOf("outcome" to "expired")
            FlowOutcome.Unknown -> mapOf("outcome" to "unknown")
        }
}

/**
 * The demo's federation fetcher: the library's [HttpFederationFetcher], whose network
 * boundary it keeps. Loopback is reached only when [anchorId] is itself on this machine —
 * the conformance tool's local federation — so that a demo pointed at a real federation
 * still refuses every internal destination.
 *
 * With [insecureTls] the TLS trust checks are DISABLED: acceptable only against the
 * conformance tool's self-signed anchor server, and so then nothing but loopback is reached.
 */
internal fun httpFetcher(
    insecureTls: Boolean,
    anchorId: String,
): FederationFetcher {
    val localFederation = runCatching { URI(anchorId).host }.getOrNull() in LOOPBACK_HOSTS
    val federation =
        HttpFederationFetcher(
            HttpDocumentFetcher(
                allowLoopback = insecureTls || localFederation,
                sslContext = if (insecureTls) trustAllTls() else null,
            ),
        )
    if (!insecureTls) return federation
    return FederationFetcher { url ->
        // The documented restriction, enforced: trust-all TLS never leaves this machine.
        val host = runCatching { URI(url).host }.getOrNull()
        check(host in LOOPBACK_HOSTS) { "insecure TLS is restricted to loopback, refused for $host" }
        federation.fetch(url)
    }
}

/** A TLS context that trusts every certificate: see [httpFetcher] for where it may be used. */
private fun trustAllTls(): SSLContext {
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
    return SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustAll), SecureRandom()) }
}

private val LOOPBACK_HOSTS = setOf("localhost", "127.0.0.1", "::1", "[::1]")
