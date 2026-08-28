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
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.net.URI

/**
 * The guided gate flow (VARCO-40): home → checklist + outcome form → signed receipt.
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

    @PostMapping("/gate/record")
    fun record(
        @RequestParam entitlement: String,
        @RequestParam operator: String,
        @RequestParam outcome: String,
    ): ResponseEntity<Void> {
        val validRequest =
            entitlement in entitlements &&
                operator.isNotBlank() &&
                operator.length <= OPERATOR_MAX_LENGTH &&
                outcome in setOf(OUTCOME_PARAM_VERIFIED, OUTCOME_PARAM_NOT_VERIFIED)
        if (!validRequest) return ResponseEntity.badRequest().build()
        val receipt = receipts.issue(entitlement, outcome == OUTCOME_PARAM_VERIFIED, operator.trim())
        return ResponseEntity
            .status(HttpStatus.FOUND)
            .location(URI.create("/gate/receipt/${receipt.id}"))
            .build()
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
        private const val OUTCOME_PARAM_VERIFIED = "verified"
        private const val OUTCOME_PARAM_NOT_VERIFIED = "not-verified"
    }
}
