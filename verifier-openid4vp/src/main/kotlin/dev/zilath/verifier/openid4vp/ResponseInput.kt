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

import dev.zilath.verifier.core.RejectionReason
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive

/*
 * Reading what a wallet posts to the response endpoint. The endpoint is unauthenticated
 * by protocol design, so everything here treats its input as an attacker's.
 */

/**
 * Refuses a response body larger than [RelyingPartyConfiguration.maxWalletResponseLength]
 * before any profile decodes it. The fourth internal review found the servlet container's
 * form limit to be the only bound: a well-formed JWE of several MiB, encrypted to the RP's
 * PUBLISHED key, was base64-decoded, decrypted and parsed in full before being rejected.
 * Checked here rather than in each profile so a third-party profile is covered too.
 */
internal fun checkWalletResponseSize(
    body: DirectPostBody,
    config: RelyingPartyConfiguration,
) {
    val length = body.parameters.entries.sumOf { (name, value) -> name.length.toLong() + value.length }
    if (length > config.maxWalletResponseLength) {
        flowReject(RejectionReason.MALFORMED, "wallet response exceeds the size limit")
    }
}

/**
 * Extracts the compact SD-JWT presentation for the requested credential from `vp_token`.
 *
 * OpenID4VP 1.0 §8.1: an object keyed by credential query id, each value an array of
 * presentations, which "MUST contain only one Presentation" unless the query set
 * `multiple` — and a [PresentationRequest] never does. So the array must hold exactly
 * one: before the fourth internal review the first element was verified and the rest
 * dropped unseen, while §14.1.2 wants every presentation in the response validated.
 * IT-Wallet (WP_093) also allows the single presentation without the array. A bare string
 * instead of the object is the legacy, pre-1.0 shape, accepted only where the profile
 * says so ([WalletProfile.acceptsBareVpToken]).
 */
internal fun extractPresentation(
    payload: JsonObject,
    credentialQueryId: String,
    acceptsBareVpToken: Boolean,
): String {
    val entry =
        when (val vpToken = payload["vp_token"]) {
            is JsonObject -> vpToken[credentialQueryId]
            is JsonPrimitive -> vpToken.takeIf { acceptsBareVpToken }
            else -> null
        }
    val presentation =
        when (entry) {
            is JsonPrimitive -> entry.stringOrNull()
            is JsonArray ->
                when (entry.size) {
                    0 -> null
                    1 -> (entry.single() as? JsonPrimitive)?.stringOrNull()
                    else -> flowReject(RejectionReason.MALFORMED, "vp_token carries more presentations than requested")
                }
            else -> null
        }
    return presentation ?: flowReject(RejectionReason.MALFORMED, "vp_token has no presentation for the query")
}

/** A presentation is a JSON string: a number or a boolean is not one, whatever its text. */
private fun JsonPrimitive.stringOrNull(): String? = content.takeIf { isString }

/**
 * Whether recording [outcome] mints a same-device response code: only where the
 * acknowledgement delivers it — a verification, and a wallet error (the user who cancelled in
 * the wallet is still sent back, RPR-59). A rejected presentation is answered with an error,
 * which carries no redirect; a code minted for it would be a live bearer secret nobody can
 * use.
 */
internal fun earnsReturnTicket(outcome: FlowOutcome): Boolean =
    outcome is FlowOutcome.Verified || outcome is FlowOutcome.WalletErrorAcknowledged

/**
 * The wallet's authorization error, in the form it may be kept and handed on.
 *
 * Both strings come from an unauthenticated POST and live in the transaction for its whole
 * time to live; the fourth internal review found them kept verbatim, at whatever size the
 * servlet container let through (2 MiB by default), where only the log line had been
 * bounded. RFC 6749 §4.1.2.1 and §5.2, which OpenID4VP §8.2 refers to, make `error` a
 * single code and restrict both parameters to %x20-21 / %x23-5B / %x5D-7E. So an `error`
 * outside that grammar, or longer than any code, becomes
 * [FlowOutcome.WalletErrorAcknowledged.MALFORMED_ERROR]; a description is cut to
 * [MAX_ERROR_DESCRIPTION_LENGTH] characters and anything outside the set becomes `?`.
 */
internal fun walletErrorOf(
    error: String,
    description: String?,
): FlowOutcome.WalletErrorAcknowledged {
    val code =
        error.takeIf { it.length in 1..MAX_ERROR_CODE_LENGTH && it.all(::isErrorResponseChar) }
            ?: FlowOutcome.WalletErrorAcknowledged.MALFORMED_ERROR
    val text =
        description
            ?.take(MAX_ERROR_DESCRIPTION_LENGTH)
            ?.map { if (isErrorResponseChar(it)) it else '?' }
            ?.joinToString("")
            ?.takeIf { it.isNotBlank() }
    return FlowOutcome.WalletErrorAcknowledged(code, text)
}

/** RFC 6749 §4.1.2.1: %x20-21 / %x23-5B / %x5D-7E — printable ASCII except `"` and `\`. */
private fun isErrorResponseChar(char: Char): Boolean =
    char == ' ' || char == '!' || char in '#'..'[' || char in ']'..'~'

/** Longer than every error code the specifications define, short enough to mean nothing else. */
private const val MAX_ERROR_CODE_LENGTH = 64

/** A sentence for a log, not a document. */
internal const val MAX_ERROR_DESCRIPTION_LENGTH = 256

/**
 * A `nonce` echoed in the response payload must match the transaction's. The binding that
 * matters is the one inside the key-binding JWT (checked by the credential verifier); this
 * is defence in depth against a response assembled for a different request.
 */
internal fun checkEchoedNonce(
    payload: JsonObject,
    transaction: Transaction,
) {
    val nonce = (payload["nonce"] as? JsonPrimitive)?.content ?: return
    if (nonce != transaction.nonce) {
        flowReject(RejectionReason.MALFORMED, "response nonce does not match the transaction")
    }
}

/** The `state` echoed by the wallet must match the transaction. */
internal fun checkState(
    payload: JsonObject,
    transaction: Transaction,
) {
    val state = (payload["state"] as? JsonPrimitive)?.jsonPrimitive?.content
    if (state != transaction.id.value) {
        flowReject(RejectionReason.MALFORMED, "response state does not match the transaction")
    }
}
