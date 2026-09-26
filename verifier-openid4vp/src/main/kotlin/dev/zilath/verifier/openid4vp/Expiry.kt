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

import java.time.Instant

/*
 * Expiry, as the flow enforces it on every path: whatever a store keeps, nothing of a
 * transaction is handed out past its expiresAt, and what is kept is redacted.
 */

/**
 * What is left of [this] once it has expired: its state, what [tombstoneOf] keeps of its
 * outcome, nothing a person could be found in — no claims, no wallet text, no response
 * code — and no decryption key.
 */
internal fun Transaction.redactedForExpiry(): Transaction =
    copy(outcome = tombstoneOf(outcome), responseCodeHash = null, responseEncryptionKey = null)

/**
 * An expired outcome loses everything a person could be found in. A rejection keeps its
 * reason and a wallet error its code; a verification is nothing but its claims, so it
 * becomes [FlowOutcome.Expired] — never a rejection, whose reason would say the credential
 * failed. Idempotent.
 */
internal fun tombstoneOf(outcome: FlowOutcome?): FlowOutcome? =
    when (outcome) {
        is FlowOutcome.Verified -> FlowOutcome.Expired
        // The detail may come from an integrator's TrustEvaluator, and from there from the
        // presentation: it has no business outliving the transaction either.
        is FlowOutcome.Rejected -> outcome.copy(detail = null)
        // The description came from the wallet response.
        is FlowOutcome.WalletErrorAcknowledged -> outcome.copy(description = null)
        else -> outcome
    }

/**
 * Whether [this] has expired at [now], or a store has already redacted it as expired: an
 * open transaction holds its own response key until a response consumes it, so an open one
 * without it was redacted — by a store whose clock read a later instant than [now] did, the
 * in-memory store's sweep among them. Taken for unexpired, it had a request object built
 * without its key — the static key in its place, or a failure when there is none — and a
 * response consumed it as if it were open.
 */
internal fun Transaction.isExpiredOrRedacted(now: Instant): Boolean =
    isExpired(now) || (state == TransactionState.CREATED && responseEncryptionKey == null)

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
