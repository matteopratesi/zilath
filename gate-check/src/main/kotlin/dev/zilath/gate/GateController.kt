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
package dev.zilath.gate

import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.net.URI

/**
 * The guided gate flow: home → checklist + outcome form → signed receipt.
 * The form has NO free-text notes on purpose: free text is where personal data leaks in.
 */
@RestController
class GateController(
    private val receipts: GateReceipts,
    @Value("\${zilath.gate.venue-name}") private val venueName: String,
    @Value("\${zilath.gate.entitlements}") entitlementsCsv: String,
) {
    private val entitlements: List<String> = entitlementsCsv.split(',').map { it.trim() }.filter { it.isNotEmpty() }

    @GetMapping("/gate", produces = [MediaType.TEXT_HTML_VALUE])
    fun home(): String = homeHtml(venueName, receipts.today().size)

    @GetMapping("/gate/new", produces = [MediaType.TEXT_HTML_VALUE])
    fun newVerification(): String = newVerificationHtml(venueName, entitlements)

    /**
     * Records one gate check. State-changing, so it refuses anything that did not come from
     * this tool's own pages.
     *
     * Binding to 127.0.0.1 keeps the network out; it does nothing about a browser ON the
     * door machine following a page that submits a form here. A cross-site form POST cannot
     * forge `Sec-Fetch-Site`, and every browser that could reach this endpoint sends it, so
     * that header is the boundary. A request without it is not a browser and is refused
     * too: nothing legitimate reaches this endpoint any other way.
     */
    @PostMapping("/gate/record")
    fun record(
        @RequestParam entitlement: String,
        @RequestParam operator: String,
        @RequestParam reference: String,
        @RequestParam outcome: String,
        @RequestHeader(name = "Sec-Fetch-Site", required = false) fetchSite: String?,
    ): ResponseEntity<Void> {
        val sameOrigin = fetchSite == "same-origin"
        // Validate what will actually be stored, not what arrived: a pasted reference with
        // surrounding whitespace was rejected for a length the trimmed value never had.
        val cleanOperator = operator.trim()
        val cleanReference = reference.trim()
        val validRequest =
            entitlement in entitlements &&
                cleanOperator.isNotBlank() &&
                cleanOperator.length <= OPERATOR_MAX_LENGTH &&
                cleanReference.isNotBlank() &&
                cleanReference.length <= REFERENCE_MAX_LENGTH &&
                !looksPersonal(cleanReference) &&
                outcome in setOf(OUTCOME_PARAM_VERIFIED, OUTCOME_PARAM_NOT_VERIFIED)
        return when {
            !sameOrigin -> ResponseEntity.status(HttpStatus.FORBIDDEN).build()
            !validRequest -> ResponseEntity.badRequest().build()
            else -> {
                val receipt =
                    receipts.issue(
                        entitlement,
                        outcome == OUTCOME_PARAM_VERIFIED,
                        cleanOperator,
                        cleanReference,
                    )
                ResponseEntity
                    .status(HttpStatus.FOUND)
                    .location(URI.create("/gate/receipt/${receipt.id}"))
                    .build()
            }
        }
    }

    @GetMapping("/gate/receipt/{id}", produces = [MediaType.TEXT_HTML_VALUE])
    fun receipt(
        @PathVariable id: String,
    ): ResponseEntity<String> {
        val receipt =
            receipts.byId(id)
                ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body(notFoundGateHtml())
        return ResponseEntity.ok(receiptHtml(venueName, receipt))
    }

    @GetMapping("/gate/today", produces = [MediaType.TEXT_HTML_VALUE])
    fun today(): String = todayHtml(venueName, receipts.today().sortedByDescending { it.issuedAt })

    companion object {
        private const val OPERATOR_MAX_LENGTH = 40
        private const val REFERENCE_MAX_LENGTH = 60

        /** An Italian tax code: six letters, then the date/place pattern, sixteen in all. */
        private val TAX_CODE = Regex("^[A-Za-z]{6}\\d{2}[A-Za-z]\\d{2}[A-Za-z]\\d{3}[A-Za-z]$")

        /**
         * Refuses the shapes of personal data this field can recognise.
         *
         * It cannot do more than that: a booking code and a surname are the same thing to a
         * regular expression, so keeping the reference free of personal data remains an
         * instruction to the operator — stated on the form, and in the README. What this
         * catches is the two cases where someone pastes the wrong thing and the mistake is
         * unambiguous.
         */
        private fun looksPersonal(reference: String): Boolean = reference.contains('@') || TAX_CODE.matches(reference)

        private const val OUTCOME_PARAM_VERIFIED = "verified"
        private const val OUTCOME_PARAM_NOT_VERIFIED = "not-verified"
    }
}
