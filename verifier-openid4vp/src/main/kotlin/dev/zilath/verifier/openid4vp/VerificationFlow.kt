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
 * by [handleWalletResponse]; the checkout page polls [awaitOutcome] with the [PollToken]
 * that [start] returned to it and to nobody else.
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
     * The request object for a wallet that asked for it with POST (OpenID4VP 1.0 §5.10),
     * carrying [walletNonce], when the wallet sent one, as its `wallet_nonce` claim — the
     * Verifier "MUST use it" there, so that the wallet can tell this object from a replayed
     * one. Null as for [requestJwtFor]. The nonce is used for this one object and kept
     * nowhere; at most [MAX_WALLET_NONCE_LENGTH] characters, and a longer one is refused with
     * [IllegalArgumentException].
     *
     * The default answers a wallet nonce with null: an implementation that cannot put it in
     * the object must not serve one without it.
     */
    fun requestJwtFor(
        txId: TransactionId,
        walletNonce: String?,
    ): String? = if (walletNonce == null) requestJwtFor(txId) else null

    /**
     * Handles the wallet's `direct_post` submission for [txId] and records the outcome.
     *
     * Terminal and single-use: the transaction's nonce is consumed here, so a replayed body
     * yields [RejectionReason.REPLAY] rather than a second success.
     *
     * The returned outcome is what THIS response met, addressed to the wallet. It is what
     * [awaitOutcome] then reports only for the first response to an open transaction, and
     * only cross-device or after the same-device return: a replay or a later error is
     * answered for itself while the checkout keeps reading the first outcome; an error
     * posted after expiry is acknowledged while the checkout reads what expiry left (see
     * [FlowOutcome]); and a same-device outcome reads [FlowOutcome.Pending] until the
     * user-agent returns.
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

    /**
     * Non-blocking snapshot of the transaction outcome, meant for checkout polling — for the
     * holder of [pollToken] only.
     *
     * The transaction id is PUBLIC by construction: it is in the QR code and the request URI
     * a bystander can photograph, and in the link a same-device user can be sent. It
     * authorises posting a response, never reading an outcome (OpenID4VP 1.0 §14.2, §14.3.3).
     * Before the fourth internal review this method took the id alone, and returned the
     * verified claims to anyone who had seen the QR.
     *
     * Cross-device, the token is [StartedTransaction.pollToken], held by the checkout that
     * started the transaction. Same-device, it is the token [consumeResponseCode] returns to
     * the user-agent that came back with the response code: the start token then reads
     * [FlowOutcome.Pending] until the return, and nothing afterwards, so a transaction
     * started by one party and completed by another person's wallet (session fixation,
     * §14.2) never shows that person's claims to the party who started it. A same-device
     * presentation that was REJECTED gets no response code, so there is no return: the start
     * token reads [FlowOutcome.Pending] until the time to live, and [FlowOutcome.Expired]
     * after it; the holder is told by the wallet, which received the error. A token that does
     * not match answers [FlowOutcome.Unknown], exactly as an id that does not exist.
     */
    fun awaitOutcome(
        txId: TransactionId,
        pollToken: PollToken,
    ): FlowOutcome

    /**
     * Completes the same-device return leg of [txId] with its single-use `code`, in one
     * atomic step, and returns the [PollToken] that from now on reads the outcome — to the
     * caller that presented the right code for the right transaction, and null for everyone
     * after (WP_094). The token replaces the one [start] returned, which stops reading
     * anything. Hand it to the user-agent that presented the code (an HttpOnly cookie), and
     * to nobody else. A code belonging to another transaction is NEVER consumed — presenting
     * it elsewhere must not burn it.
     */
    fun consumeResponseCode(
        txId: TransactionId,
        code: String,
    ): PollToken?

    companion object {
        /**
         * The longest `wallet_nonce` a request object repeats. OpenID4VP sets no length; a
         * nonce is some tens of characters, and the limit keeps what an unauthenticated
         * caller can have the relying party sign small.
         */
        const val MAX_WALLET_NONCE_LENGTH: Int = 256
    }
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
     * is exactly one call per transaction, and only when that outcome is
     * [FlowOutcome.Verified] or [FlowOutcome.WalletErrorAcknowledged]: the code is minted in
     * the same atomic update that records the outcome. Null for cross-device transactions,
     * for a replay, for an error posted after the outcome was reached or after expiry, and
     * for a [FlowOutcome.Rejected] presentation — which the endpoint answers with an error,
     * a response that carries no redirect, so the user-agent does not come back through the
     * callback and the start token reads [FlowOutcome.Pending] and then
     * [FlowOutcome.Expired] (see [VerificationFlow.awaitOutcome]).
     *
     * The FIRST response to an open transaction records its outcome, whoever posts it: the
     * transaction id authorises posting, and an `error` from someone who knows only the id,
     * posted before the wallet answers, records a [FlowOutcome.WalletErrorAcknowledged] and
     * is handed its ticket — the wallet's own response then meets a replay, the terminal
     * denial the unauthenticated endpoint allows by design. Every response after the first
     * is owed an acknowledgement, never a return ticket.
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
 * Identifies one verification transaction. Travels as the OpenID4VP `state`, in the request
 * URI inside the QR code and in the response URI: it is PUBLIC by construction, visible to
 * anyone who sees the checkout's screen or the link a user was sent.
 *
 * It authorises posting to the response endpoint, which is unauthenticated by protocol
 * design — including an `error`, which terminally ends the transaction. It never
 * authorises reading an outcome: that takes the [PollToken].
 */
data class TransactionId(
    val value: String,
)

/**
 * The right to read one transaction's outcome through [VerificationFlow.awaitOutcome]: 32
 * random bytes that appear in no QR code, request object, `state` or response URI.
 *
 * Keep it where only the party entitled to the outcome has it — the checkout's server-side
 * session, or an HttpOnly cookie on the browser that started (cross-device) or returned to
 * (same-device) the transaction — and out of URLs and logs. The flow stores only its hash.
 */
data class PollToken(
    val value: String,
) {
    override fun toString(): String = "PollToken(***)"
}

/**
 * What the relying party asks the wallet to present: ONE credential, described by the
 * single Credential Query of a DCQL query.
 *
 * The query is read when the request is constructed, and a query this library cannot
 * evaluate is refused there with [IllegalArgumentException]: no `credentials` array, not
 * exactly one credential query, one not named [credentialQueryId], a `format` other than
 * `dc+sd-jwt` (or the pre-1.0 `vc+sd-jwt`), no `meta` object with a non-empty `vct_values`,
 * `credential_sets`, `multiple: true`, `trusted_authorities`,
 * `require_cryptographic_holder_binding: false`, or `claims`/`claim_sets` that do not follow
 * OpenID4VP 1.0 §6 and §7. Before the fourth internal review such a query passed
 * [VerificationFlow.start], reached the wallet inside the signed request, and then failed
 * every response as an internal error; a query asking for two credentials verified one and
 * ignored the other; and one without `vct_values` switched the credential type check off.
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
     * `meta.vct_values` for the credential query this request names: never empty, since a
     * query without them is refused.
     *
     * The query is the statement of what was asked for; deriving the check from it means
     * the two cannot drift apart.
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
    /**
     * Reads the outcome through [VerificationFlow.awaitOutcome]: cross-device until the end,
     * same-device only until the user-agent returns (then [VerificationFlow.consumeResponseCode]
     * issues the token that reads it). Never show it to the wallet or put it in the QR.
     */
    val pollToken: PollToken,
) {
    override fun toString(): String = "StartedTransaction(id=${id.value}, requestUri=$requestUri, qrPayload=$qrPayload)"
}

/** The raw form parameters posted by the wallet to the response endpoint. */
data class DirectPostBody(
    val parameters: Map<String, String>,
) {
    /** The encrypted response JWE (`direct_post.jwt` mode, mandatory in IT-Wallet). */
    val response: String? get() = parameters["response"]

    /**
     * The parameter NAMES, never their values. Under [ArfBaselineProfile] the `vp_token` is
     * posted in plaintext, with every disclosure the holder made, and a data class prints
     * all of it; the values are unauthenticated input besides, of any size.
     */
    override fun toString(): String = "DirectPostBody(parameters=${parameters.keys})"
}

/**
 * Where a transaction stands. Everything except [Pending] is terminal, and a terminal value
 * changes only when the transaction expires, to lose what a person could be found in: a
 * [Verified] reads [Expired] from then on, a [Rejected] loses its detail and a
 * [WalletErrorAcknowledged] its description.
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
     * The presentation was verified. [claims] holds the requested claims that are present
     * (for a query without `claims`, what the holder disclosed), plus `iss` and `vct`, and
     * nothing else of the issuer envelope — the credential itself is already gone by the
     * time this is returned.
     */
    data class Verified(
        val claims: DisclosedClaims,
    ) : FlowOutcome {
        /** The NAMES of the disclosed claims, never their values: an outcome ends up in logs. */
        override fun toString(): String = "Verified(claims=${claims.claims.keys})"
    }

    /**
     * The presentation arrived but did not pass. As in [dev.zilath.verifier.core.VerificationResult.Rejected],
     * [detail] is for logs and must not be echoed to the person at the checkout. It is one
     * of the library's fixed phrases, the verifier's or the flow's own, with two exceptions:
     * for [RejectionReason.UNTRUSTED_ISSUER] it is the TrustEvaluator's reason, cut to 200
     * characters with control characters replaced; and a CredentialVerifier of the
     * application's own writes whatever it writes. Once the transaction expires, [detail] is
     * dropped and [reason] stays.
     */
    data class Rejected(
        val reason: RejectionReason,
        val detail: String? = null,
    ) : FlowOutcome

    /**
     * The transaction exceeded its time to live: before completing, or after a verification,
     * whose claims are not handed out past it.
     */
    data object Expired : FlowOutcome

    /** No transaction with the given id exists, or none the given [PollToken] may read: the two answer alike. */
    data object Unknown : FlowOutcome
}
