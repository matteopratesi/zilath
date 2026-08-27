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
import dev.varco.verifier.openid4vp.FlowMode
import dev.varco.verifier.openid4vp.FlowOutcome
import dev.varco.verifier.openid4vp.PresentationRequest
import dev.varco.verifier.openid4vp.TransactionId
import dev.varco.verifier.openid4vp.VerificationFlow
import dev.varco.verifier.openid4vp.VerificationReceipts
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
import javax.imageio.ImageIO

/**
 * The "fake checkout" demo (plan docs/03 §5-M0.5): event page, companion-ticket button,
 * QR for the wallet, polling, NOMINATIVE fake ticket and signed verification receipt.
 */
@RestController
class DemoCheckoutController(
    private val flow: VerificationFlow,
    private val receipts: VerificationReceipts,
    private val clock: java.time.Clock,
    @Value("\${varco.demo.pid-vct:urn:eu.europa.ec.eudi:pid:1}") private val pidVct: String,
    @Value("\${varco.demo.credential-mode:pid}") private val credentialMode: String,
) {
    /** Started transactions, kept a bit longer than the flow TTL so receipts stay downloadable. */
    private val registry = DemoTransactionRegistry(clock, REGISTRY_TIME_TO_LIVE)

    @GetMapping("/demo", produces = [MediaType.TEXT_HTML_VALUE])
    fun eventPage(): String = eventPageHtml()

    @GetMapping("/demo/entitled")
    fun startEntitledPurchase(
        @org.springframework.web.bind.annotation.RequestParam(defaultValue = "cross-device") flow: String,
    ): ResponseEntity<Void> {
        val request =
            if (credentialMode == CED_SIM_MODE) {
                PresentationRequest.forVct(
                    dev.varco.demo.cedsim.CedSim.VCT,
                    dev.varco.demo.cedsim.CedSim.CLAIM_PATHS,
                    dev.varco.demo.cedsim.CedSim.CREDENTIAL_QUERY_ID,
                )
            } else {
                PresentationRequest.forTestPid(pidVct)
            }
        val mode = if (flow == SAME_DEVICE_PARAM) FlowMode.SAME_DEVICE else FlowMode.CROSS_DEVICE
        val transaction = this.flow.start(request, mode)
        registry.register(transaction, request)
        return ResponseEntity
            .status(HttpStatus.FOUND)
            .location(URI.create("/demo/wait/${transaction.id.value}"))
            .build()
    }

    @GetMapping("/demo/wait/{txId}", produces = [MediaType.TEXT_HTML_VALUE])
    fun waitPage(
        @PathVariable txId: String,
    ): ResponseEntity<String> {
        val entry = registry.get(txId) ?: return notFoundPage()
        val walletCommand =
            if (credentialMode == CED_SIM_MODE) {
                "./scripts/run-ced-wallet.sh $txId"
            } else {
                "./scripts/run-demo-wallet.sh $txId"
            }
        return ResponseEntity.ok(waitPageHtml(txId, entry.transaction.qrPayload, walletCommand))
    }

    @GetMapping("/demo/qr/{txId}.png", produces = [MediaType.IMAGE_PNG_VALUE])
    fun qrCode(
        @PathVariable txId: String,
    ): ResponseEntity<ByteArray> {
        val entry = registry.get(txId) ?: return ResponseEntity.notFound().build()
        return ResponseEntity.ok(qrPng(entry.transaction.qrPayload))
    }

    @GetMapping("/demo/authorize-url/{txId}", produces = [MediaType.TEXT_PLAIN_VALUE])
    fun authorizeUrl(
        @PathVariable txId: String,
    ): ResponseEntity<String> {
        val entry = registry.get(txId) ?: return ResponseEntity.notFound().build()
        return ResponseEntity.ok(entry.transaction.qrPayload)
    }

    @GetMapping("/demo/status/{txId}", produces = [MediaType.APPLICATION_JSON_VALUE])
    fun status(
        @PathVariable txId: String,
    ): Map<String, String> {
        val outcome = flow.awaitOutcome(TransactionId(txId))
        recordReceiptIfTerminal(txId, outcome)
        return mapOf(
            "status" to
                when (outcome) {
                    FlowOutcome.Pending -> "pending"
                    is FlowOutcome.Verified -> "verified"
                    is FlowOutcome.Rejected, is FlowOutcome.WalletErrorAcknowledged -> "rejected"
                    FlowOutcome.Expired -> "expired"
                    FlowOutcome.Unknown -> "unknown"
                },
        )
    }

    @GetMapping("/demo/ticket/{txId}", produces = [MediaType.TEXT_HTML_VALUE])
    fun ticket(
        @PathVariable txId: String,
    ): ResponseEntity<String> {
        val outcome = flow.awaitOutcome(TransactionId(txId))
        recordReceiptIfTerminal(txId, outcome)
        return when {
            outcome !is FlowOutcome.Verified ->
                ResponseEntity.status(HttpStatus.CONFLICT).body(notVerifiedHtml(txId))
            // The DCQL only asks for disclosure: the VALUE of the entitlement is enforced here.
            credentialMode == CED_SIM_MODE &&
                !dev.varco.demo.cedsim.CedSim
                    .entitlementGranted(outcome.claims.claims, clock) ->
                ResponseEntity.status(HttpStatus.CONFLICT).body(notEntitledHtml(txId))
            else -> ResponseEntity.ok(verifiedTicketHtml(txId, outcome.claims.claims))
        }
    }

    /** Same-device return leg: the wallet redirects here with the single-use code. */
    @GetMapping("/demo/cb")
    fun sameDeviceCallback(
        @org.springframework.web.bind.annotation.RequestParam("response_code") responseCode: String,
    ): ResponseEntity<String> {
        val txId =
            flow.consumeResponseCode(responseCode)
                ?: return notFoundPage()
        return ResponseEntity
            .status(HttpStatus.FOUND)
            .location(URI.create("/demo/ticket/${'$'}{txId.value}"))
            .build<Void>()
            .let {
                ResponseEntity
                    .status(
                        HttpStatus.FOUND,
                    ).location(URI.create("/demo/ticket/${'$'}{txId.value}"))
                    .body("")
            }
    }

    @GetMapping("/demo/receipt/{txId}", produces = [MediaType.TEXT_PLAIN_VALUE])
    fun receipt(
        @PathVariable txId: String,
    ): ResponseEntity<String> {
        val entry = registry.get(txId) ?: return ResponseEntity.notFound().build()
        recordReceiptIfTerminal(txId, flow.awaitOutcome(TransactionId(txId)))
        return when (val receipt = entry.receipt.get()) {
            null -> ResponseEntity.status(HttpStatus.CONFLICT).body("transaction not completed")
            else -> ResponseEntity.ok(receipt)
        }
    }

    /** The receipt is signed ONCE, when the terminal outcome is first observed. */
    private fun recordReceiptIfTerminal(
        txId: String,
        outcome: FlowOutcome,
    ) {
        val verified =
            when (outcome) {
                is FlowOutcome.Verified -> true
                is FlowOutcome.Rejected, is FlowOutcome.WalletErrorAcknowledged -> false
                else -> return
            }
        registry.receiptFor(txId) { request -> receipts.issue(TransactionId(txId), request, verified) }
    }

    companion object {
        private val REGISTRY_TIME_TO_LIVE: java.time.Duration = java.time.Duration.ofMinutes(15)
        private const val CED_SIM_MODE = "ced-sim"
        private const val SAME_DEVICE_PARAM = "same-device"
    }
}

private fun notFoundPage(): ResponseEntity<String> = ResponseEntity.status(HttpStatus.NOT_FOUND).body(notFoundHtml())

/** Renders a QR PNG without pulling the zxing `javase` artifact in. */
internal fun qrPng(payload: String): ByteArray {
    val matrix = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, QR_SIZE, QR_SIZE)
    val image = BufferedImage(QR_SIZE, QR_SIZE, BufferedImage.TYPE_INT_RGB)
    for (x in 0 until QR_SIZE) {
        for (y in 0 until QR_SIZE) {
            image.setRGB(x, y, if (matrix.get(x, y)) QR_BLACK else QR_WHITE)
        }
    }
    val out = ByteArrayOutputStream()
    ImageIO.write(image, "png", out)
    return out.toByteArray()
}

private const val QR_SIZE = 320
private const val QR_BLACK = 0x000000
private const val QR_WHITE = 0xFFFFFF
