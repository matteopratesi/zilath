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
import dev.zilath.verifier.core.RequestedClaims
import kotlinx.serialization.json.JsonObject
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
     *
     * Each call also allocates server-side state for the time to live, on behalf of
     * whoever reached the page that calls it: rate-limit it or bind it to a session. The
     * default store refuses beyond its capacity with [TooManyTransactionsException].
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
     * The result also carries what the acknowledgement to the wallet needs: for a
     * same-device transaction, the `redirect_uri` with its single-use `response_code` —
     * minted by, and handed to, ONLY the call whose response recorded the outcome (see
     * [HandledResponse.redirectUri]).
     *
     * Note for the endpoint on top of this: a [FlowOutcome.WalletErrorAcknowledged] must
     * be answered with HTTP 200, because OpenID4VP wants the error acknowledged rather
     * than re-reported. The status code an endpoint returns is in any case addressed to
     * the WALLET; the verdict the checkout acts on comes from [awaitOutcome].
     */
    fun handleWalletResponse(
        txId: TransactionId,
        body: DirectPostBody,
    ): HandledResponse

    /** Non-blocking snapshot of the transaction outcome, meant for checkout polling. */
    fun awaitOutcome(txId: TransactionId): FlowOutcome

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

/**
 * What [VerificationFlow.handleWalletResponse] did with one wallet POST: the [outcome], and
 * what the acknowledgement to the wallet carries.
 */
data class HandledResponse(
    val outcome: FlowOutcome,
    /**
     * The same-device `redirect_uri` for the acknowledgement (IT-Wallet 1.4.6 remote flow,
     * WP_094): callback base, transaction id, and a single-use `response_code` — the return
     * ticket of the user-agent that completed the presentation.
     *
     * Present only for the call whose response RECORDED the transaction's outcome, which
     * is exactly one call per transaction: the code is minted in the same atomic update that
     * records the outcome. Null for cross-device transactions, for a replay, for an error
     * posted after the outcome was reached or after expiry. Anyone knowing the transaction
     * id may post an `error`; that request is owed an acknowledgement, never a return ticket.
     * The fourth internal review found the ticket handed to whichever later caller presented
     * an outcome EQUAL to the recorded one — `access_denied`, the only error a cancelling
     * wallet sends, is easy to guess — and lost for the legitimate user whenever a store did
     * not keep the outcome bit for bit, or served the read-back from a lagging replica.
     */
    val redirectUri: String? = null,
) {
    /** The redirect carries a bearer code: say whether there is one, never what it is. */
    override fun toString(): String =
        "HandledResponse(outcome=$outcome, redirectUri=${if (redirectUri == null) "none" else "set"})"
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

/**
 * What the relying party asks the wallet to present: ONE credential, described by the
 * single Credential Query of a DCQL query.
 *
 * The query is read when the request is constructed, and a query this library cannot
 * evaluate is refused there with [IllegalArgumentException]: no `credentials` array, not
 * exactly one credential query, one not named [credentialQueryId], `credential_sets`,
 * `multiple: true`, or `claims`/`claim_sets`/`vct_values` that do not follow OpenID4VP 1.0
 * §6 and §7. Before the fourth internal review such a query passed [VerificationFlow.start],
 * reached the wallet inside the signed request, and then failed every response as an
 * internal error; a query asking for two credentials verified one and ignored the other.
 */
data class PresentationRequest(
    /** A DCQL query as required by IT-Wallet v1.4.x (`dcql_query` claim). */
    val dcqlQuery: JsonObject,
    /** The id of the credential query inside [dcqlQuery], used to pick the vp_token entry. */
    val credentialQueryId: String,
) {
    // Read once, here, so that construction is the validation. Not constructor properties:
    // equality and copies stay those of the query itself.
    private val credentialQuery: JsonObject = credentialQueryOf(dcqlQuery, credentialQueryId)
    private val vctValues: Set<String> = vctValuesOf(credentialQuery)
    private val claims: RequestedClaims? = requestedClaimsOf(credentialQuery)

    /**
     * The credential types this request will accept, read back out of the DCQL query's
     * `meta.vct_values` for the credential query this request names.
     *
     * The query is the statement of what was asked for; deriving the check from it means
     * the two cannot drift apart. An empty result — a caller-built query that does not
     * constrain the type — leaves the verifier unconstrained too, rather than rejecting.
     */
    fun expectedVcts(): Set<String> = vctValues

    /**
     * The claims this request asks for, from the credential query's `claims` and
     * `claim_sets`, for [dev.zilath.verifier.core.VerificationContext.requestedClaims].
     * Null when the query names no claims.
     */
    fun requestedClaims(): RequestedClaims? = claims

    companion object {
        /**
         * DCQL query for a single SD-JWT VC type: [claimPaths] are top-level claim names
         * (nested paths can be expressed with the full [PresentationRequest] constructor).
         * No claim paths means no `claims` member: DCQL does not allow an empty array.
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
                            if (claimPaths.isNotEmpty()) {
                                putJsonArray("claims") {
                                    claimPaths.forEach { path ->
                                        addJsonObject { putJsonArray("path") { add(path) } }
                                    }
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
     *
     * Both values come from an unauthenticated request and are bounded before they are
     * kept: [error] is the wallet's code when it is one (RFC 6749 §4.1.2.1 grammar, at most
     * 64 characters) and [MALFORMED_ERROR] otherwise; [description] is at most 256
     * characters of that grammar, anything else replaced by `?`.
     */
    data class WalletErrorAcknowledged(
        val error: String,
        val description: String? = null,
    ) : FlowOutcome {
        companion object {
            /** Stands in for an `error` parameter that is not an error code. */
            const val MALFORMED_ERROR = "malformed_error"
        }
    }

    /**
     * The presentation was verified. [claims] holds what the wallet disclosed for this query
     * plus `iss` and `vct`, and nothing else of the issuer envelope — the credential itself
     * is already gone by the time this is returned.
     */
    data class Verified(
        val claims: DisclosedClaims,
    ) : FlowOutcome {
        /** The NAMES of the disclosed claims, never their values: an outcome ends up in logs. */
        override fun toString(): String = "Verified(claims=${claims.claims.keys})"
    }

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
