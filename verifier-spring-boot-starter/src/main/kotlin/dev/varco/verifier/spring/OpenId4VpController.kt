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
package dev.varco.verifier.spring

import dev.varco.verifier.openid4vp.DirectPostBody
import dev.varco.verifier.openid4vp.FlowOutcome
import dev.varco.verifier.openid4vp.TransactionId
import dev.varco.verifier.openid4vp.VerificationFlow
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

    /** Receives the wallet's encrypted `direct_post.jwt` response. */
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
            is FlowOutcome.Verified -> ResponseEntity.ok(emptyMap())
            is FlowOutcome.Rejected -> {
                // detail is a server-side diagnostic: only the reason code reaches the wallet.
                logger.warn("wallet response rejected: {} ({})", outcome.reason, outcome.detail)
                badRequest(outcome.reason.name)
            }
            FlowOutcome.Expired -> badRequest("transaction expired")
            FlowOutcome.Pending -> badRequest("response not processable")
            FlowOutcome.Unknown -> ResponseEntity.notFound().build()
        }

    private fun badRequest(description: String): ResponseEntity<Map<String, String>> =
        ResponseEntity
            .badRequest()
            .body(mapOf("error" to "invalid_request", "error_description" to description))

    companion object {
        const val REQUEST_OBJECT_MEDIA_TYPE = "application/oauth-authz-req+jwt"
        private val logger = org.slf4j.LoggerFactory.getLogger(OpenId4VpController::class.java)
    }
}
