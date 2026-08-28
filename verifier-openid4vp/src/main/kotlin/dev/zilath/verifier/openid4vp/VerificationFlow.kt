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
package dev.zilath.verifier.openid4vp

import dev.zilath.verifier.core.DisclosedClaims
import dev.zilath.verifier.core.RejectionReason
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * The OpenID4VP relying-party flow (cross-device, IT-Wallet profile v1.4.5):
 * [start] creates a transaction and yields the QR payload; the wallet fetches the
 * signed request JWT via [requestJwtFor] and posts its encrypted response, handled
 * by [handleWalletResponse]; the checkout page polls [awaitOutcome].
 *
 * Nothing about a presentation survives the transaction: outcomes carry only the
 * disclosed claims, and transactions expire from the [TransactionStore].
 */
interface VerificationFlow {
    /**
     * Opens a transaction for [request] and returns everything needed to send the user to
     * their wallet.
     *
     * Each call mints a fresh nonce and a fresh transaction id: never reuse a
     * [StartedTransaction] across users or page loads, because the nonce is what binds one
     * presentation to one request and it is accepted exactly once.
     */
    fun start(
        request: PresentationRequest,
        mode: FlowMode = FlowMode.CROSS_DEVICE,
    ): StartedTransaction

    /**
     * The signed request object (JAR) the wallet retrieves from `request_uri`,
     * or null if the transaction is unknown, already consumed, or expired.
     */
    fun requestJwtFor(txId: TransactionId): String?

    /**
     * Handles the wallet's `direct_post` submission for [txId] and records the outcome.
     *
     * Terminal and single-use: the transaction's nonce is consumed here, so a replayed body
     * yields [RejectionReason.REPLAY] rather than a second success. The returned outcome is
     * also what [awaitOutcome] will report from now on.
     *
     * Note for the endpoint on top of this: a [FlowOutcome.WalletErrorAcknowledged] must
     * be answered with HTTP 200, because OpenID4VP wants the error acknowledged rather
     * than re-reported. The status code an endpoint returns is in any case addressed to
     * the WALLET; the verdict the checkout acts on comes from [awaitOutcome].
     */
    fun handleWalletResponse(
        txId: TransactionId,
        body: DirectPostBody,
    ): FlowOutcome

    /** Non-blocking snapshot of the transaction outcome, meant for checkout polling. */
    fun awaitOutcome(txId: TransactionId): FlowOutcome

    /**
     * The same-device `redirect_uri` for the wallet response acknowledgement (spec
     * v1.4.6, remote flow): callback base + a fresh single-use `response_code`.
     * Null for cross-device transactions and for transactions without a recorded
     * outcome. Idempotent: repeated calls return the same code.
     */
    fun sameDeviceRedirectFor(txId: TransactionId): String?

    /**
     * Completes the same-device return leg of [txId] with its single-use `code`, in one
     * atomic step: true only for the caller that presented the right code for the right
     * transaction, false for everyone after (WP_094). A code belonging to another
     * transaction is NEVER consumed — presenting it elsewhere must not burn it.
     */
    fun consumeResponseCode(
        txId: TransactionId,
        code: String,
    ): Boolean
}

/** How the user reaches the wallet: QR on another device, or a link on the same one. */
enum class FlowMode { CROSS_DEVICE, SAME_DEVICE }

/**
 * Identifies one verification transaction. Travels as the OpenID4VP `state` and appears in
 * the response URI, so it is public by construction: it is an opaque handle, never a
 * capability — knowing an id grants nothing on its own.
 */
data class TransactionId(
    val value: String,
)

/** What the relying party asks the wallet to present. */
data class PresentationRequest(
    /** A DCQL query as required by IT-Wallet v1.4.5 (`dcql_query` claim). */
    val dcqlQuery: JsonObject,
    /** The id of the credential query inside [dcqlQuery], used to pick the vp_token entry. */
    val credentialQueryId: String,
) {
    companion object {
        /**
         * DCQL query for a single SD-JWT VC type: [claimPaths] are top-level claim names
         * (nested paths can be expressed with the full [PresentationRequest] constructor).
         */
        fun forVct(
            vct: String,
            claimPaths: List<String>,
            credentialQueryId: String,
        ): PresentationRequest {
            val dcql =
                buildJsonObject {
                    putJsonArray("credentials") {
                        addJsonObject {
                            put("id", credentialQueryId)
                            put("format", "dc+sd-jwt")
                            putJsonObject("meta") {
                                putJsonArray("vct_values") { add(vct) }
                            }
                            putJsonArray("claims") {
                                claimPaths.forEach { path ->
                                    addJsonObject { putJsonArray("path") { add(path) } }
                                }
                            }
                        }
                    }
                }
            return PresentationRequest(dcql, credentialQueryId)
        }

        /**
         * Minimal query for the test PID (plan docs/03 §5-M0.3): given name and family
         * name only. The production vct is confirmed against the conformance tool in M0.4.
         */
        fun forTestPid(vct: String): PresentationRequest = forVct(vct, listOf("given_name", "family_name"), "pid")
    }
}

/** Everything the checkout needs to render the QR and start polling. */
data class StartedTransaction(
    val id: TransactionId,
    /** Where the wallet fetches the request JWT (JAR by reference). */
    val requestUri: String,
    /** The full URI to encode in the QR code. */
    val qrPayload: String,
)

/** The raw form parameters posted by the wallet to the response endpoint. */
data class DirectPostBody(
    val parameters: Map<String, String>,
) {
    /** The encrypted response JWE (`direct_post.jwt` mode, mandatory in IT-Wallet). */
    val response: String? get() = parameters["response"]
}

/**
 * Where a transaction stands. Everything except [Pending] is terminal, and the terminal
 * value never changes afterwards.
 */
sealed interface FlowOutcome {
    /** The wallet has not answered yet. */
    data object Pending : FlowOutcome

    /**
     * The wallet sent an authorization error response (e.g. `access_denied`): terminal,
     * and acknowledged with HTTP 200 as OpenID4VP requires for `direct_post`.
     */
    data class WalletErrorAcknowledged(
        val error: String,
        val description: String? = null,
    ) : FlowOutcome

    /**
     * The presentation was verified. [claims] holds only what the wallet disclosed for this
     * query — the credential itself is already gone by the time this is returned.
     */
    data class Verified(
        val claims: DisclosedClaims,
    ) : FlowOutcome

    /**
     * The presentation arrived but did not pass. As in [dev.zilath.verifier.core.VerificationResult.Rejected],
     * [detail] is for logs and must not be echoed to the person at the checkout.
     */
    data class Rejected(
        val reason: RejectionReason,
        val detail: String? = null,
    ) : FlowOutcome

    /** The transaction exceeded its time to live before completing. */
    data object Expired : FlowOutcome

    /** No transaction with the given id exists. */
    data object Unknown : FlowOutcome
}
