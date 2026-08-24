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
package dev.varco.demo

import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import dev.varco.verifier.openid4vp.FlowOutcome
import dev.varco.verifier.openid4vp.PresentationRequest
import dev.varco.verifier.openid4vp.StartedTransaction
import dev.varco.verifier.openid4vp.TransactionId
import dev.varco.verifier.openid4vp.VerificationFlow
import dev.varco.verifier.openid4vp.VerificationReceipts
import kotlinx.serialization.json.jsonPrimitive
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RestController
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.net.URI
import java.util.concurrent.ConcurrentHashMap
import javax.imageio.ImageIO

/**
 * The "fake checkout" demo (plan docs/03 §5-M0.5): event page, companion-ticket button,
 * QR for the wallet, polling, NOMINATIVE fake ticket and signed verification receipt.
 */
@RestController
class DemoCheckoutController(
    private val flow: VerificationFlow,
    private val receipts: VerificationReceipts,
    @Value("\${varco.demo.pid-vct:urn:eu.europa.ec.eudi:pid:1}") private val pidVct: String,
) {
    /** The demo keeps the started transactions so it can render QR codes and receipts. */
    private val started = ConcurrentHashMap<String, Pair<StartedTransaction, PresentationRequest>>()

    @GetMapping("/demo", produces = [MediaType.TEXT_HTML_VALUE])
    fun eventPage(): String = eventPageHtml()

    @GetMapping("/demo/entitled")
    fun startEntitledPurchase(): ResponseEntity<Void> {
        val request = PresentationRequest.forTestPid(pidVct)
        val transaction = flow.start(request)
        started[transaction.id.value] = transaction to request
        return ResponseEntity
            .status(HttpStatus.FOUND)
            .location(URI.create("/demo/wait/${transaction.id.value}"))
            .build()
    }

    @GetMapping("/demo/wait/{txId}", produces = [MediaType.TEXT_HTML_VALUE])
    fun waitPage(
        @PathVariable txId: String,
    ): ResponseEntity<String> {
        val (transaction, _) = started[txId] ?: return notFoundPage()
        return ResponseEntity.ok(waitPageHtml(txId, transaction.qrPayload))
    }

    @GetMapping("/demo/qr/{txId}.png", produces = [MediaType.IMAGE_PNG_VALUE])
    fun qrCode(
        @PathVariable txId: String,
    ): ResponseEntity<ByteArray> {
        val (transaction, _) = started[txId] ?: return ResponseEntity.notFound().build()
        return ResponseEntity.ok(qrPng(transaction.qrPayload))
    }

    @GetMapping("/demo/authorize-url/{txId}", produces = [MediaType.TEXT_PLAIN_VALUE])
    fun authorizeUrl(
        @PathVariable txId: String,
    ): ResponseEntity<String> {
        val (transaction, _) = started[txId] ?: return ResponseEntity.notFound().build()
        return ResponseEntity.ok(transaction.qrPayload)
    }

    @GetMapping("/demo/status/{txId}", produces = [MediaType.APPLICATION_JSON_VALUE])
    fun status(
        @PathVariable txId: String,
    ): Map<String, String> =
        mapOf(
            "status" to
                when (flow.awaitOutcome(TransactionId(txId))) {
                    FlowOutcome.Pending -> "pending"
                    is FlowOutcome.Verified -> "verified"
                    is FlowOutcome.Rejected, is FlowOutcome.WalletErrorAcknowledged -> "rejected"
                    FlowOutcome.Expired -> "expired"
                    FlowOutcome.Unknown -> "unknown"
                },
        )

    @GetMapping("/demo/ticket/{txId}", produces = [MediaType.TEXT_HTML_VALUE])
    fun ticket(
        @PathVariable txId: String,
    ): ResponseEntity<String> {
        val outcome = flow.awaitOutcome(TransactionId(txId))
        if (outcome !is FlowOutcome.Verified) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(notVerifiedHtml(txId))
        }
        val claims = outcome.claims.claims
        val holder =
            listOfNotNull(
                claims["given_name"]?.jsonPrimitive?.content,
                claims["family_name"]?.jsonPrimitive?.content,
            ).joinToString(" ").ifBlank { "—" }
        return ResponseEntity.ok(ticketHtml(txId, holder))
    }

    @GetMapping("/demo/receipt/{txId}", produces = [MediaType.TEXT_PLAIN_VALUE])
    fun receipt(
        @PathVariable txId: String,
    ): ResponseEntity<String> {
        val (_, request) = started[txId] ?: return ResponseEntity.notFound().build()
        return when (flow.awaitOutcome(TransactionId(txId))) {
            is FlowOutcome.Verified -> ResponseEntity.ok(receipts.issue(TransactionId(txId), request, true))
            is FlowOutcome.Rejected, is FlowOutcome.WalletErrorAcknowledged ->
                ResponseEntity.ok(receipts.issue(TransactionId(txId), request, false))
            else -> ResponseEntity.status(HttpStatus.CONFLICT).body("transaction not completed")
        }
    }

    private fun notFoundPage(): ResponseEntity<String> =
        ResponseEntity.status(HttpStatus.NOT_FOUND).body(notFoundHtml())

    private fun qrPng(payload: String): ByteArray {
        val matrix = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, QR_SIZE, QR_SIZE)
        val image = BufferedImage(QR_SIZE, QR_SIZE, BufferedImage.TYPE_INT_RGB)
        for (x in 0 until QR_SIZE) {
            for (y in 0 until QR_SIZE) {
                image.setRGB(x, y, if (matrix.get(x, y)) BLACK else WHITE)
            }
        }
        val out = ByteArrayOutputStream()
        ImageIO.write(image, "png", out)
        return out.toByteArray()
    }

    companion object {
        private const val QR_SIZE = 320
        private const val BLACK = 0x000000
        private const val WHITE = 0xFFFFFF
    }
}
