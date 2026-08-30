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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * The OpenID4VP relying-party flow (cross-device, IT-Wallet profile v1.4.x):
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
     * v1.4.6, remote flow): callback base + a single-use `response_code`.
     *
     * [outcome] must be the outcome [handleWalletResponse] just returned to this caller,
     * and the code is released only when it still matches the one recorded on the
     * transaction. That parameter is the security boundary, not a convenience: without it
     * any acknowledgement — including the one owed to an unauthenticated `error` POST —
     * would hand out the return ticket for whatever outcome the transaction happened to
     * hold, which for a completed same-device verification is somebody's verified
     * entitlement.
     *
     * Null for cross-device transactions, for a transaction with no recorded outcome, for
     * one whose return leg is already done or expired, and for any caller presenting an
     * outcome that is not the recorded one. Idempotent for the caller it belongs to.
     */
    fun sameDeviceRedirectFor(
        txId: TransactionId,
        outcome: FlowOutcome,
    ): String?

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
 * the response URI.
 *
 * Treat it as a BEARER CAPABILITY, not as a public handle. The response endpoint is
 * unauthenticated by protocol design, so whoever holds this id can post to it — including
 * an `error`, which terminally ends the transaction. That is inherent to OpenID4VP: the id
 * is 16 random bytes precisely because unguessability is what protects the exchange. Do not
 * put it anywhere it can leak — a referrer, an analytics URL, a log shipped off the box.
 */
data class TransactionId(
    val value: String,
)

/** What the relying party asks the wallet to present. */
data class PresentationRequest(
    /** A DCQL query as required by IT-Wallet v1.4.x (`dcql_query` claim). */
    val dcqlQuery: JsonObject,
    /** The id of the credential query inside [dcqlQuery], used to pick the vp_token entry. */
    val credentialQueryId: String,
) {
    /**
     * The credential types this request will accept, read back out of the DCQL query's
     * `meta.vct_values` for the credential query this request names.
     *
     * The query is the statement of what was asked for; deriving the check from it means
     * the two cannot drift apart. An empty result — a caller-built query that does not
     * constrain the type — leaves the verifier unconstrained too, rather than rejecting.
     */
    fun expectedVcts(): Set<String> {
        // No runCatching here, deliberately. Swallowing a parse failure would return the
        // empty set, and the empty set means "do not check the credential type" — so a
        // malformed query would silently switch off a security check instead of failing.
        // That is the same fail-open this audit found elsewhere, and a query this library
        // cannot read is the relying party's own bug, which should surface at start().
        val credentials =
            requireNotNull(dcqlQuery["credentials"] as? JsonArray) {
                "dcql_query has no credentials array"
            }
        val matching =
            credentials
                .mapNotNull { it as? JsonObject }
                .filter { (it["id"] as? JsonPrimitive)?.content == credentialQueryId }
        require(matching.isNotEmpty()) { "dcql_query has no credential with id $credentialQueryId" }
        return matching
            .flatMap { credential ->
                ((credential["meta"] as? JsonObject)?.get("vct_values") as? JsonArray)
                    .orEmpty()
                    .mapNotNull { (it as? JsonPrimitive)?.content }
            }.toSet()
    }

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
         * Minimal query for the test PID: given name and family name only. The vct is
         * the caller's to supply — it differs between the conformance mock and production.
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
