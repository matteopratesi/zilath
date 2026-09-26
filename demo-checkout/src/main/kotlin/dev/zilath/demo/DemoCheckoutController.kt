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

import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import dev.zilath.demo.cedsim.CedSim
import dev.zilath.verifier.openid4vp.FlowMode
import dev.zilath.verifier.openid4vp.FlowOutcome
import dev.zilath.verifier.openid4vp.PollToken
import dev.zilath.verifier.openid4vp.PresentationRequest
import dev.zilath.verifier.openid4vp.ReceiptOutcome
import dev.zilath.verifier.openid4vp.TransactionId
import dev.zilath.verifier.openid4vp.VerificationFlow
import dev.zilath.verifier.openid4vp.VerificationReceipts
import jakarta.servlet.http.HttpServletRequest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.CacheControl
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseCookie
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.CookieValue
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.net.URI
import java.security.SecureRandom
import java.util.Base64
import javax.imageio.ImageIO

/**
 * The "fake checkout" demo: event page, companion-ticket button,
 * QR for the wallet, polling, NOMINATIVE fake ticket and signed verification receipt.
 *
 * Every page about a transaction answers only the browser that started it (IT-Wallet 1.4.6
 * §12.2.1.7): starting one sets a session cookie, and the waiting page, the QR, the status,
 * the ticket, the receipt and the same-device return all ask for it. The transaction id is no
 * key — it is in the QR on the screen and in the same-device link — and before the fourth
 * internal review anyone who had seen it read the holder's name and entitlement here.
 */
@RestController
class DemoCheckoutController(
    private val flow: VerificationFlow,
    private val receipts: VerificationReceipts,
    private val clock: java.time.Clock,
    @Value("\${zilath.demo.pid-vct:urn:eu.europa.ec.eudi:pid:1}") private val pidVct: String,
    @Value("\${zilath.demo.credential-mode:pid}") private val credentialMode: String,
) {
    /** Started transactions, kept a bit longer than the flow TTL so receipts stay downloadable. */
    private val registry = DemoTransactionRegistry(clock, REGISTRY_TIME_TO_LIVE)

    @GetMapping("/demo", produces = [MediaType.TEXT_HTML_VALUE])
    fun eventPage(): String = eventPageHtml()

    @GetMapping("/demo/entitled")
    fun startEntitledPurchase(
        @RequestParam(defaultValue = "cross-device") flow: String,
        @CookieValue(name = SESSION_COOKIE, required = false) session: String?,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<Void> {
        val request =
            if (credentialMode == CED_SIM_MODE) {
                PresentationRequest.forVct(CedSim.VCT, CedSim.CLAIM_PATHS, CedSim.CREDENTIAL_QUERY_ID)
            } else {
                PresentationRequest.forTestPid(pidVct)
            }
        val mode = if (flow == SAME_DEVICE_PARAM) FlowMode.SAME_DEVICE else FlowMode.CROSS_DEVICE
        val transaction = this.flow.start(request, mode)
        // One secret per browser: a second purchase in the same browser keeps the first readable.
        val secret = session?.takeIf(SESSION_SECRET::matches) ?: newSessionSecret()
        registry.register(transaction, request, secret)
        return ResponseEntity
            .status(HttpStatus.FOUND)
            .location(URI.create("/demo/wait/${transaction.id.value}"))
            .header(HttpHeaders.SET_COOKIE, sessionCookie(secret, httpRequest).toString())
            .build()
    }

    @GetMapping("/demo/wait/{txId}", produces = [MediaType.TEXT_HTML_VALUE])
    fun waitPage(
        @PathVariable txId: String,
        @CookieValue(name = SESSION_COOKIE, required = false) session: String?,
    ): ResponseEntity<String> {
        val entry = registry.ownedValid(txId, session) ?: return notFoundPage()
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
        @CookieValue(name = SESSION_COOKIE, required = false) session: String?,
    ): ResponseEntity<ByteArray> {
        val entry = registry.ownedValid(txId, session) ?: return ResponseEntity.notFound().build()
        return ResponseEntity.ok(qrPng(entry.transaction.qrPayload))
    }

    @GetMapping("/demo/authorize-url/{txId}", produces = [MediaType.TEXT_PLAIN_VALUE])
    fun authorizeUrl(
        @PathVariable txId: String,
        @CookieValue(name = SESSION_COOKIE, required = false) session: String?,
    ): ResponseEntity<String> {
        val entry = registry.ownedValid(txId, session) ?: return ResponseEntity.notFound().build()
        return ResponseEntity.ok(entry.transaction.qrPayload)
    }

    @GetMapping("/demo/status/{txId}", produces = [MediaType.APPLICATION_JSON_VALUE])
    fun status(
        @PathVariable txId: String,
        @CookieValue(name = SESSION_COOKIE, required = false) session: String?,
    ): Map<String, String> {
        // Another browser's transaction reads as one that does not exist.
        val outcome = registry.ownedValid(txId, session)?.let { flow.outcomeOf(txId, it) } ?: FlowOutcome.Unknown
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
        @CookieValue(name = SESSION_COOKIE, required = false) session: String?,
    ): ResponseEntity<String> {
        val entry = registry.ownedValid(txId, session) ?: return notFoundPage()
        val outcome = flow.outcomeOf(txId, entry)
        val decided = decisionFor(outcome)?.also { registry.issueReceipt(txId, it, receipts) }
        return when {
            outcome !is FlowOutcome.Verified ->
                ResponseEntity.status(HttpStatus.CONFLICT).body(notVerifiedHtml(txId))
            decided == ReceiptOutcome.VERIFIED_NOT_ENTITLED ->
                ResponseEntity.status(HttpStatus.CONFLICT).body(notEntitledHtml(txId))
            else -> ResponseEntity.ok(verifiedTicketHtml(txId, outcome.claims.claims))
        }
    }

    /**
     * Same-device return leg: the wallet redirects the user-agent here with the
     * single-use code. The order of the checks matters — an unknown session and an
     * invalid code are told apart, and an error carried in the query never consumes
     * the code (spec v1.4.6, remote flow; RP-side status semantics).
     */
    @GetMapping("/demo/cb/{txId}")
    fun sameDeviceCallback(
        @PathVariable txId: String,
        @RequestParam(name = "response_code", required = false) responseCode: String?,
        @RequestParam(required = false) error: String?,
        @CookieValue(name = SESSION_COOKIE, required = false) session: String?,
    ): ResponseEntity<String> {
        val entry = registry.get(txId)
        return when {
            error != null -> ResponseEntity.badRequest().body(callbackErrorHtml(error))
            responseCode.isNullOrBlank() || !TRANSACTION_ID.matches(txId) -> unauthorizedPage()
            // A transaction these pages started is completed only by the browser that started
            // it: someone sent the link of another person's transaction (session fixation,
            // OpenID4VP 1.0 §14.2) comes back without its cookie, and the code stays unspent.
            entry != null && !entry.ownedBy(session) -> unauthorizedPage()
            // Asked for any other id: the flow redeems a code only on its own transaction and
            // leaves another's untouched. A transaction these pages did not start — a
            // conformance run — completes its return too, and gets no ticket page: the token
            // that reads its outcome from now on goes to this user-agent, the one that came
            // back, as the flow means it to.
            else ->
                when (val reader = flow.consumeResponseCode(TransactionId(txId), responseCode)) {
                    null ->
                        if (entry == null) {
                            unauthorizedPage()
                        } else {
                            ResponseEntity.badRequest().body(callbackErrorHtml("invalid_response_code"))
                        }
                    else ->
                        if (entry == null) {
                            ResponseEntity
                                .ok()
                                .contentType(MediaType.APPLICATION_JSON)
                                .cacheControl(CacheControl.noStore())
                                .body(returnedJson(reader))
                        } else {
                            entry.readToken.set(reader)
                            ResponseEntity
                                .status(HttpStatus.FOUND)
                                .location(URI.create("/demo/ticket/" + txId))
                                .build()
                        }
                }
        }
    }

    @GetMapping("/demo/receipt/{txId}", produces = [MediaType.TEXT_PLAIN_VALUE])
    fun receipt(
        @PathVariable txId: String,
        @CookieValue(name = SESSION_COOKIE, required = false) session: String?,
    ): ResponseEntity<String> {
        val entry = registry.ownedValid(txId, session) ?: return ResponseEntity.notFound().build()
        decisionFor(flow.outcomeOf(txId, entry))?.let { registry.issueReceipt(txId, it, receipts) }
        return entry.receipt.get()?.let { ResponseEntity.ok(it) }
            ?: ResponseEntity.status(HttpStatus.CONFLICT).body("transaction not completed")
    }

    /**
     * The demo's policy, applied before anything is signed. The DCQL only asks for disclosure,
     * so the VALUE of the entitlement is decided here, and the receipt states that decision:
     * it used to be signed on the first status poll, before the policy ran, and a card that
     * verified without the entitlement was archived as one that had it.
     */
    private fun decisionFor(outcome: FlowOutcome): ReceiptOutcome? =
        when (outcome) {
            is FlowOutcome.Verified ->
                if (credentialMode != CED_SIM_MODE || CedSim.entitlementGranted(outcome.claims.claims, clock)) {
                    ReceiptOutcome.VERIFIED_ENTITLED
                } else {
                    ReceiptOutcome.VERIFIED_NOT_ENTITLED
                }
            is FlowOutcome.Rejected, is FlowOutcome.WalletErrorAcknowledged -> ReceiptOutcome.REJECTED
            else -> null
        }

    companion object {
        private val REGISTRY_TIME_TO_LIVE: java.time.Duration = java.time.Duration.ofMinutes(15)
        private const val CED_SIM_MODE = "ced-sim"
        private const val SAME_DEVICE_PARAM = "same-device"

        /** The cookie that binds the demo's transactions to the browser that started them. */
        const val SESSION_COOKIE = "zilath_demo_session"
    }
}

/** The entry for [txId] if the browser holding [session] started it; a malformed id is nobody's. */
private fun DemoTransactionRegistry.ownedValid(
    txId: String,
    session: String?,
): DemoTransactionRegistry.Entry? = txId.takeIf(TRANSACTION_ID::matches)?.let { ownedEntry(it, session) }

private fun VerificationFlow.outcomeOf(
    txId: String,
    entry: DemoTransactionRegistry.Entry,
): FlowOutcome = awaitOutcome(TransactionId(txId), entry.readToken.get())

/** The receipt is signed ONCE, when the terminal outcome is first observed. */
private fun DemoTransactionRegistry.issueReceipt(
    txId: String,
    outcome: ReceiptOutcome,
    receipts: VerificationReceipts,
) {
    receiptFor(txId) { request -> receipts.issue(TransactionId(txId), request, outcome) }
}

/** The alphabet of the flow's transaction ids (base64url), bounded: anything else is no transaction. */
private val TRANSACTION_ID = Regex("[A-Za-z0-9_-]{1,128}")

/** A session secret as [newSessionSecret] makes it: 32 random bytes, base64url. */
private val SESSION_SECRET = Regex("[A-Za-z0-9_-]{43}")

private val secureRandom = SecureRandom()

private fun newSessionSecret(): String =
    Base64
        .getUrlEncoder()
        .withoutPadding()
        .encodeToString(ByteArray(SESSION_SECRET_BYTES).also(secureRandom::nextBytes))

/**
 * HttpOnly, SameSite=Lax — the same-device return is a top-level navigation, which Lax lets
 * through — and Secure, except over plain http on a loopback host, the local setup the demo
 * instructions use, where there is no TLS for the flag to ask for.
 */
private fun sessionCookie(
    secret: String,
    httpRequest: HttpServletRequest,
): ResponseCookie =
    ResponseCookie
        .from(DemoCheckoutController.SESSION_COOKIE, secret)
        .httpOnly(true)
        .secure(httpRequest.isSecure || httpRequest.serverName !in LOOPBACK_NAMES)
        .sameSite("Lax")
        .path("/demo")
        .build()

private val LOOPBACK_NAMES = setOf("localhost", "127.0.0.1", "::1", "[::1]")

private const val SESSION_SECRET_BYTES = 32

/** What a user-agent that came back for a transaction these pages did not start is handed. */
private fun returnedJson(reader: PollToken): String =
    JsonObject(mapOf("status" to JsonPrimitive("returned"), "pollToken" to JsonPrimitive(reader.value))).toString()

private fun notFoundPage(): ResponseEntity<String> = ResponseEntity.status(HttpStatus.NOT_FOUND).body(notFoundHtml())

private fun unauthorizedPage(): ResponseEntity<String> =
    ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(callbackErrorHtml("unauthorized_session"))

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
