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
import java.time.Instant

/*
 * Expiry, as the flow enforces it on every path: whatever a store keeps, nothing of a
 * transaction is handed out past its expiresAt, and what is kept is redacted.
 */

/**
 * What is left of [this] once it has expired: its kind and state, nothing a person could be
 * found in — no claims, no wallet text, no response code — and no decryption key.
 */
internal fun Transaction.redactedForExpiry(): Transaction =
    copy(outcome = tombstoneOf(outcome), responseCode = null, responseEncryptionKey = null)

/** An expired outcome keeps its kind and loses everything a person could be found in. Idempotent. */
internal fun tombstoneOf(outcome: FlowOutcome?): FlowOutcome? =
    when (outcome) {
        is FlowOutcome.Verified -> FlowOutcome.Rejected(RejectionReason.EXPIRED)
        // The detail may come from an integrator's TrustEvaluator, and from there from the
        // presentation: it has no business outliving the transaction either.
        is FlowOutcome.Rejected -> outcome.copy(detail = null)
        // The description came from the wallet response.
        is FlowOutcome.WalletErrorAcknowledged -> outcome.copy(description = null)
        else -> outcome
    }

/**
 * Redacts the transaction [txId] in place if it has expired at [now], and returns what the
 * store holds afterwards. Kept, not removed, so that later reads answer Expired rather than
 * Unknown until the store drops the entry; redacted, so that nothing in it outlives its
 * time to live. Decided from the value the store replaced, never from a side effect of the
 * update function (which a store may run more than once).
 */
internal fun TransactionStore.redactIfExpired(
    txId: TransactionId,
    now: Instant,
): Transaction? =
    compareAndUpdate(txId) { current -> if (current.isExpired(now)) current.redactedForExpiry() else current }
        ?.let { previous -> if (previous.isExpired(now)) previous.redactedForExpiry() else previous }

/**
 * What the wallet is answered for a response that met an expired transaction: Expired, but
 * a wallet error is still acknowledged as itself, as OpenID4VP §8.2 owes it.
 */
internal fun answerAfterExpiry(outcome: FlowOutcome): FlowOutcome =
    if (outcome is FlowOutcome.WalletErrorAcknowledged) outcome else FlowOutcome.Expired

/** What the checkout is told about an expired transaction: never a claim, never the wallet's text. */
internal fun expiredAnswerFor(transaction: Transaction): FlowOutcome =
    when {
        transaction.outcome == null -> FlowOutcome.Expired
        // An unreturned same-device outcome was never the checkout's to see (WP_094).
        transaction.mode == FlowMode.SAME_DEVICE && !transaction.returned -> FlowOutcome.Expired
        else -> tombstoneOf(transaction.outcome) ?: FlowOutcome.Expired
    }
