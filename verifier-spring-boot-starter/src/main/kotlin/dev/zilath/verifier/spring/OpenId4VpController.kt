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
import dev.zilath.verifier.core.RejectionReason
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

/**
 * The wallet-facing endpoints of the IT-Wallet flow: the request object, by GET or by POST,
 * and the wallet's response.
 */
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
    ): ResponseEntity<*> = requestObjectAnswer(flow.requestJwtFor(TransactionId(txId)))

    /**
     * The request object for a wallet that asks for it with POST (OpenID4VP 1.0 §5.10), as
     * the QR payload announces with `request_uri_method=post`: the object the GET serves,
     * with the wallet's `wallet_nonce`, when it sends one, as its `wallet_nonce` claim.
     *
     * `wallet_metadata` describes the holder's wallet, and nothing in it changes what this
     * relying party asks for or accepts: it has one set of algorithms and formats, which
     * every request object publishes. So it is bounded, and never parsed, logged or kept.
     * Before the fourth internal review POST was not served at all: conformant, since a
     * wallet falls back to GET, but a wallet could not have its own nonce in the object.
     */
    @PostMapping("/openid4vp/request/{txId}", consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE])
    fun requestObjectByPost(
        @PathVariable txId: String,
        @RequestParam(name = "wallet_metadata", required = false) walletMetadata: String?,
        @RequestParam(name = "wallet_nonce", required = false) walletNonce: String?,
    ): ResponseEntity<*> =
        when {
            (walletMetadata?.length ?: 0) > MAX_WALLET_METADATA_LENGTH ->
                errorAnswer(HttpStatus.BAD_REQUEST, INVALID_REQUEST, "wallet_metadata is too large")
            (walletNonce?.length ?: 0) > VerificationFlow.MAX_WALLET_NONCE_LENGTH ->
                errorAnswer(HttpStatus.BAD_REQUEST, INVALID_REQUEST, "wallet_nonce is too long")
            else -> requestObjectAnswer(flow.requestJwtFor(TransactionId(txId), walletNonce))
        }

    /**
     * The request object, or the answer IT-Wallet 1.4.6 §12.2.1.3.1 gives when there is none
     * to serve — unknown, consumed or expired alike: 400 `invalid_request` with a JSON body,
     * where a bare 404 used to be.
     */
    private fun requestObjectAnswer(requestObject: String?): ResponseEntity<*> =
        requestObject?.let { uncached(HttpStatus.OK).contentType(REQUEST_OBJECT_TYPE).body(it) }
            ?: errorAnswer(HttpStatus.BAD_REQUEST, INVALID_REQUEST, NOT_AVAILABLE)

    /**
     * Receives the wallet's encrypted `direct_post.jwt` response, and answers as IT-Wallet
     * 1.4.6 §12.2.1.6.1 tabulates:
     * - 200 for a verified presentation and for an acknowledged wallet error (the ack
     *   OpenID4VP requires, carrying the same-device `redirect_uri` when there is one);
     * - 403 `invalid_request` for a presentation whose key binding, nonce, audience, issuer
     *   signature or issuer trust failed;
     * - 500 `server_error` when the verification pipeline itself failed;
     * - 400 `invalid_request` for every other rejection and for an expired transaction;
     * - 404, with the same JSON shape, for a transaction that does not exist.
     *
     * The `error_description` is one fixed phrase per status: which check failed, and the
     * rejection's `detail`, stay server-side, in the log. Before the fourth internal review
     * every rejection was a 400 naming its [RejectionReason], an oracle telling a prober
     * which check a crafted presentation failed. The verdict the CHECKOUT acts on is not
     * this status code: it comes from [VerificationFlow.awaitOutcome].
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
                // The reason and the detail are server-side diagnostics: the wallet gets the status.
                logger.warn("wallet response rejected: {} ({})", outcome.reason, forLog(outcome.detail))
                rejection(outcome.reason)
            }
            FlowOutcome.Expired, FlowOutcome.Pending -> errorAnswer(HttpStatus.BAD_REQUEST, INVALID_REQUEST, NOT_VALID)
            FlowOutcome.Unknown -> errorAnswer(HttpStatus.NOT_FOUND, INVALID_REQUEST, UNKNOWN_TRANSACTION)
        }
    }

    private fun rejection(reason: RejectionReason): ResponseEntity<Map<String, String>> =
        when (reason) {
            in FORBIDDEN_REASONS -> errorAnswer(HttpStatus.FORBIDDEN, INVALID_REQUEST, NOT_ACCEPTED)
            RejectionReason.INTERNAL_ERROR -> errorAnswer(HttpStatus.INTERNAL_SERVER_ERROR, SERVER_ERROR, NOT_PROCESSED)
            // An open enum: a reason added later is a 400 until it is placed.
            else -> errorAnswer(HttpStatus.BAD_REQUEST, INVALID_REQUEST, NOT_VALID)
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

    private fun errorAnswer(
        status: HttpStatus,
        code: String,
        description: String,
    ): ResponseEntity<Map<String, String>> = json(status, mapOf("error" to code, "error_description" to description))

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

        /**
         * The rejections IT-Wallet 1.4.6 §12.2.1.6.1 answers with 403: the key binding's
         * signature, the nonce and the trust in the credential issuer, with the audience of
         * the key binding and the issuer's signature beside them.
         */
        private val FORBIDDEN_REASONS: Set<RejectionReason> =
            setOf(
                RejectionReason.INVALID_KEY_BINDING,
                RejectionReason.NONCE_MISMATCH,
                RejectionReason.AUDIENCE_MISMATCH,
                RejectionReason.UNTRUSTED_ISSUER,
                RejectionReason.INVALID_ISSUER_SIGNATURE,
            )

        private const val INVALID_REQUEST = "invalid_request"
        private const val SERVER_ERROR = "server_error"
        private const val NOT_VALID = "the wallet response is not valid"
        private const val NOT_ACCEPTED = "the presentation was not accepted"
        private const val NOT_PROCESSED = "the wallet response could not be processed"
        private const val UNKNOWN_TRANSACTION = "unknown transaction"
        private const val NOT_AVAILABLE = "request object not available"

        /**
         * Room for any wallet's metadata (OpenID4VP 1.0 §10: formats, algorithms, a key set)
         * many times over: its length is all that is read of it.
         */
        private const val MAX_WALLET_METADATA_LENGTH = 64 * 1024
        private val logger = org.slf4j.LoggerFactory.getLogger(OpenId4VpController::class.java)
    }
}
