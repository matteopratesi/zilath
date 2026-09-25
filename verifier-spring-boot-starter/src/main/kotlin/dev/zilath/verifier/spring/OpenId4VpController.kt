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
package dev.zilath.verifier.spring

import dev.zilath.verifier.core.InternalZilathApi
import dev.zilath.verifier.core.boundedPrintable
import dev.zilath.verifier.openid4vp.DirectPostBody
import dev.zilath.verifier.openid4vp.FlowOutcome
import dev.zilath.verifier.openid4vp.HandledResponse
import dev.zilath.verifier.openid4vp.TransactionId
import dev.zilath.verifier.openid4vp.VerificationFlow
import org.springframework.http.CacheControl
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.util.MultiValueMap
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

/** The two wallet-facing endpoints of the IT-Wallet cross-device flow. */
@RestController
class OpenId4VpController(
    private val flow: VerificationFlow,
) {
    /**
     * Serves the signed request object (JAR by reference), as
     * `application/oauth-authz-req+jwt` whatever the wallet's `Accept` says.
     *
     * No `produces`: the specifications fix the type of the response (OpenID4VP 1.0
     * §5.10.1, RFC 9101 §5.2), not what the wallet must accept, and IT-Wallet's GET carries
     * no requirement on `Accept`. The fourth internal review found Spring's negotiation
     * answering a wallet that sent `Accept: application/jwt` with 406 and an empty body: a
     * holder that could never present.
     */
    @GetMapping("/openid4vp/request/{txId}")
    fun requestObject(
        @PathVariable txId: String,
    ): ResponseEntity<String> {
        val requestObject = flow.requestJwtFor(TransactionId(txId)) ?: return uncached(HttpStatus.NOT_FOUND).build()
        return uncached(HttpStatus.OK).contentType(REQUEST_OBJECT_TYPE).body(requestObject)
    }

    /**
     * Receives the wallet's encrypted `direct_post.jwt` response.
     *
     * HTTP 200 for a verified presentation and for an acknowledged wallet error (the ack
     * OpenID4VP requires, carrying the same-device `redirect_uri` when there is one);
     * HTTP 400 with the [dev.zilath.verifier.core.RejectionReason] name for a rejection,
     * an expired transaction or an unprocessable one; HTTP 404 for an unknown transaction.
     *
     * What the wallet gets back is only ever the coarse reason code — `detail` stays
     * server-side, in the log. The verdict the CHECKOUT acts on is not this status code:
     * it comes from [VerificationFlow.awaitOutcome].
     */
    @PostMapping("/openid4vp/response/{txId}", consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE])
    fun walletResponse(
        @PathVariable txId: String,
        @RequestParam parameters: MultiValueMap<String, String>,
    ): ResponseEntity<Map<String, String>> {
        val handled = flow.handleWalletResponse(TransactionId(txId), DirectPostBody(parameters.toSingleValueMap()))
        return when (val outcome = handled.outcome) {
            is FlowOutcome.Verified -> json(HttpStatus.OK, ackBody(handled))
            is FlowOutcome.WalletErrorAcknowledged -> {
                // OpenID4VP direct_post: wallet error responses are acknowledged with 200.
                // In the same-device flow the ack still carries the redirect_uri, so the
                // user lands back on the RP even after cancelling in the wallet (RPR-59).
                logger.info("wallet error response acknowledged: {}", forLog(outcome.error))
                json(HttpStatus.OK, ackBody(handled))
            }
            is FlowOutcome.Rejected -> {
                // detail is a server-side diagnostic: only the reason code reaches the wallet.
                logger.warn("wallet response rejected: {} ({})", outcome.reason, forLog(outcome.detail))
                badRequest(outcome.reason.name)
            }
            FlowOutcome.Expired -> badRequest("transaction expired")
            FlowOutcome.Pending -> badRequest("response not processable")
            FlowOutcome.Unknown -> uncached(HttpStatus.NOT_FOUND).build()
        }
    }

    /**
     * Same-device transactions are acknowledged with their redirect_uri (spec v1.4.6), which
     * the flow hands only to the request whose response recorded the outcome — see
     * [dev.zilath.verifier.openid4vp.HandledResponse.redirectUri].
     */
    private fun ackBody(handled: HandledResponse): Map<String, String> =
        handled.redirectUri?.let { mapOf("redirect_uri" to it) } ?: emptyMap()

    /**
     * Anyone who knows a transaction id can post to the response endpoint, and what it posts
     * reaches the log: the wallet's `error`, and a rejection's `detail`, which a
     * [dev.zilath.verifier.core.TrustEvaluator] or a [dev.zilath.verifier.core.CredentialVerifier]
     * of the application's may write from the presentation. Both go through the library's one
     * rule for text it did not write, so that an unauthenticated caller can neither forge log
     * lines nor flood the file. The fourth internal review found the detail logged raw, and
     * the error bounded by a second copy of that rule.
     */
    @OptIn(InternalZilathApi::class)
    private fun forLog(value: String?): String = boundedPrintable(value.orEmpty())

    private fun badRequest(description: String): ResponseEntity<Map<String, String>> =
        json(HttpStatus.BAD_REQUEST, mapOf("error" to "invalid_request", "error_description" to description))

    /**
     * JSON, whatever the wallet's `Accept` says: an acknowledgement it cannot negotiate away
     * is one fewer way for a holder to be refused.
     */
    private fun json(
        status: HttpStatus,
        body: Map<String, String>,
    ): ResponseEntity<Map<String, String>> = uncached(status).contentType(MediaType.APPLICATION_JSON).body(body)

    /**
     * Every answer of both endpoints is meant for one wallet, once, and two of them carry
     * secrets: the request object its nonce and `state`, the same-device acknowledgement the
     * single-use response code. `no-store` keeps them out of any cache between the wallet and
     * the relying party (RFC 9111 §5.2.2.5) — a cache with no rule for these paths would
     * otherwise keep serving a request object after its transaction was consumed — and
     * `Pragma` does the same for HTTP/1.0 caches (§5.4). The fourth internal review found no
     * cache directive at all; the error answers carry them too, for uniformity.
     */
    private fun uncached(status: HttpStatus): ResponseEntity.BodyBuilder =
        ResponseEntity
            .status(status)
            .cacheControl(CacheControl.noStore())
            .header(HttpHeaders.PRAGMA, "no-cache")

    companion object {
        const val REQUEST_OBJECT_MEDIA_TYPE = "application/oauth-authz-req+jwt"
        private val REQUEST_OBJECT_TYPE = MediaType.parseMediaType(REQUEST_OBJECT_MEDIA_TYPE)
        private val logger = org.slf4j.LoggerFactory.getLogger(OpenId4VpController::class.java)
    }
}
