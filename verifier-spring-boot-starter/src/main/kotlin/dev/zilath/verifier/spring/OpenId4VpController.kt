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

import dev.zilath.verifier.openid4vp.DirectPostBody
import dev.zilath.verifier.openid4vp.FlowOutcome
import dev.zilath.verifier.openid4vp.TransactionId
import dev.zilath.verifier.openid4vp.VerificationFlow
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.util.MultiValueMap
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

/** The two wallet-facing endpoints of the IT-Wallet cross-device flow (plan docs/03 §5-M0.3). */
@RestController
class OpenId4VpController(
    private val flow: VerificationFlow,
) {
    /** Serves the signed request object (JAR by reference). */
    @GetMapping("/openid4vp/request/{txId}", produces = [REQUEST_OBJECT_MEDIA_TYPE])
    fun requestObject(
        @PathVariable txId: String,
    ): ResponseEntity<String> =
        flow.requestJwtFor(TransactionId(txId))?.let { ResponseEntity.ok(it) }
            ?: ResponseEntity.notFound().build()

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
    @PostMapping(
        "/openid4vp/response/{txId}",
        consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE],
        produces = [MediaType.APPLICATION_JSON_VALUE],
    )
    fun walletResponse(
        @PathVariable txId: String,
        @RequestParam parameters: MultiValueMap<String, String>,
    ): ResponseEntity<Map<String, String>> =
        when (
            val outcome =
                flow.handleWalletResponse(
                    TransactionId(txId),
                    DirectPostBody(parameters.toSingleValueMap()),
                )
        ) {
            is FlowOutcome.Verified -> ResponseEntity.ok(ackBody(txId))
            is FlowOutcome.WalletErrorAcknowledged -> {
                // OpenID4VP direct_post: wallet error responses are acknowledged with 200.
                // In the same-device flow the ack still carries the redirect_uri, so the
                // user lands back on the RP even after cancelling in the wallet (RPR-59).
                logger.info("wallet error response acknowledged: {}", forLog(outcome.error))
                ResponseEntity.ok(ackBody(txId))
            }
            is FlowOutcome.Rejected -> {
                // detail is a server-side diagnostic: only the reason code reaches the wallet.
                logger.warn("wallet response rejected: {} ({})", outcome.reason, outcome.detail)
                badRequest(outcome.reason.name)
            }
            FlowOutcome.Expired -> badRequest("transaction expired")
            FlowOutcome.Pending -> badRequest("response not processable")
            FlowOutcome.Unknown -> ResponseEntity.notFound().build()
        }

    /** Same-device transactions are acknowledged with their redirect_uri (spec v1.4.6). */
    private fun ackBody(txId: String): Map<String, String> =
        flow.sameDeviceRedirectFor(TransactionId(txId))?.let { mapOf("redirect_uri" to it) } ?: emptyMap()

    /**
     * Anyone who knows a transaction id can put an arbitrary string in `error` and have it
     * written to the log. Bound the length and strip the control characters, so an
     * unauthenticated caller cannot forge log lines or flood the file.
     */
    private fun forLog(value: String?): String =
        value
            .orEmpty()
            .take(MAX_LOGGED_ERROR)
            .map { if (it.isISOControl()) '?' else it }
            .joinToString("")

    private fun badRequest(description: String): ResponseEntity<Map<String, String>> =
        ResponseEntity
            .badRequest()
            .body(mapOf("error" to "invalid_request", "error_description" to description))

    companion object {
        const val REQUEST_OBJECT_MEDIA_TYPE = "application/oauth-authz-req+jwt"
        private val logger = org.slf4j.LoggerFactory.getLogger(OpenId4VpController::class.java)

        private const val MAX_LOGGED_ERROR = 200
    }
}
