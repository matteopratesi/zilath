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
package dev.varco.verifier.openid4vp

import dev.varco.verifier.core.DisclosedClaims
import dev.varco.verifier.core.RejectionReason
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

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
    fun start(request: PresentationRequest): StartedTransaction

    /**
     * The signed request object (JAR) the wallet retrieves from `request_uri`,
     * or null if the transaction is unknown, already consumed, or expired.
     */
    fun requestJwtFor(txId: TransactionId): String?

    fun handleWalletResponse(
        txId: TransactionId,
        body: DirectPostBody,
    ): FlowOutcome

    /** Non-blocking snapshot of the transaction outcome, meant for checkout polling. */
    fun awaitOutcome(txId: TransactionId): FlowOutcome
}

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
         * Minimal query for the test PID (plan docs/03 §5-M0.3): given name and family
         * name only. The production vct is confirmed against the conformance tool in M0.4.
         */
        fun forTestPid(vct: String): PresentationRequest {
            val dcql =
                """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "meta": { "vct_values": ["$vct"] },
                      "claims": [
                        { "path": ["given_name"] },
                        { "path": ["family_name"] }
                      ]
                    }
                  ]
                }
                """.trimIndent()
            return PresentationRequest(Json.parseToJsonElement(dcql) as JsonObject, "pid")
        }
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

sealed interface FlowOutcome {
    /** The wallet has not answered yet. */
    data object Pending : FlowOutcome

    data class Verified(
        val claims: DisclosedClaims,
    ) : FlowOutcome

    data class Rejected(
        val reason: RejectionReason,
        val detail: String? = null,
    ) : FlowOutcome

    /** The transaction exceeded its time to live before completing. */
    data object Expired : FlowOutcome

    /** No transaction with the given id exists. */
    data object Unknown : FlowOutcome
}
