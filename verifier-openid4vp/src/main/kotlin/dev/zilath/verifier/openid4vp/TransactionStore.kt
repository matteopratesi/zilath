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

import com.nimbusds.jose.jwk.ECKey
import java.time.Instant

/**
 * Keeps in-flight transactions between [VerificationFlow.start] and the wallet response.
 *
 * The default, [InMemoryTransactionStore], serves one process. A deployment with more than
 * one node needs a shared store of its own, and the flow's guarantees — a nonce accepted
 * once, a response code consumed once, a same-device user sent back to the relying party —
 * hold only if that store has these properties:
 *
 * 1. **Previous value.** [compareAndUpdate] returns the value it REPLACED, never the one it
 *    stored, and null only when no entry existed at the moment the operation took effect.
 *    (Returning the new value, as `computeIfPresent` does, turns every presentation into a
 *    replay without a single error.)
 * 2. **Linearizable per id.** Concurrent updates of one entry take effect one after the
 *    other, each applied to the result of the one before: none is lost, none applied twice.
 * 3. **Re-runnable update.** The update function may be invoked more than once, as an
 *    optimistic store does when it retries; the flow's functions are pure for that reason.
 *    Only the invocation whose result is committed counts, and the value returned is the
 *    one THAT invocation received.
 * 4. **Read-your-writes.** [get] observes every [put], [compareAndUpdate] and [remove] that
 *    has already returned, from any thread or node: a read served by a lagging replica is
 *    not allowed.
 * 5. **Lossless.** A transaction reads back equal to what was written — every field, the
 *    [FlowOutcome] and its claims included (instants to the millisecond at least).
 * 6. **Retention.** Keep an entry at least until its [Transaction.expiresAt] — dropping it
 *    earlier refuses a holder whose request object is still valid — and remove it within a
 *    bounded time after. Keeping it a little longer lets the flow answer Expired rather
 *    than Unknown; [InMemoryTransactionStore] keeps it one more minute. Expiry itself is
 *    not the store's to decide: the flow checks [Transaction.expiresAt] on every read and
 *    never returns claims past it, whatever the store hands back. What an expired entry
 *    still HOLDS is the store's, though: the flow redacts it only when it next touches the
 *    transaction (see [Transaction]), so a store that keeps expired entries should redact
 *    them at [Transaction.expiresAt], as the in-memory one does, or remove them then.
 *
 * `TransactionStoreContractTest` checks properties 1 to 5 — not retention, which a generic
 * test cannot observe without waiting on the store's own clock: extend it with a factory for
 * your store and run it. It is in the Zilath repository, in the test fixtures of
 * `verifier-openid4vp` (`src/testFixtures`), and NOT on Maven Central, where test fixtures
 * are not published: copy it into your tests — it needs only JUnit 5 and AssertJ — or build
 * Zilath from source. The fourth internal review found the
 * list implicit and unchecked, and plausible stores breaking it — an eventually consistent
 * read, a minimising codec, the new value in place of the old — with nothing in the
 * library to notice.
 *
 * What a transaction holds is not only nonces: the request; the hashes of the poll token and
 * of the response code; the transaction's PRIVATE response-encryption key, until the first
 * response or expiry; and, once verified, an [Transaction.outcome] carrying the claims
 * [dev.zilath.verifier.core.VerificationResult.Verified] hands over, until
 * [Transaction.expiresAt], past which no read returns them. Treat any store, and its logs,
 * accordingly.
 */
interface TransactionStore {
    /** Stores [transaction], replacing any entry with the same id. */
    fun put(transaction: Transaction)

    /**
     * Returns the stored transaction, or null if it is absent — including, once the store
     * has removed it, one that expired (property 6). What it returns for an expired entry
     * need not be redacted: the flow does that, and writes the redaction back.
     */
    fun get(id: TransactionId): Transaction?

    /**
     * Atomically applies [update] to the stored transaction and returns the value it
     * replaced, or null if there was none — properties 1 to 3 above. The flow consumes the
     * nonce and the response code through this, and decides from the returned value.
     */
    fun compareAndUpdate(
        id: TransactionId,
        update: (Transaction) -> Transaction,
    ): Transaction?

    /** Drops the transaction if present. Idempotent. */
    fun remove(id: TransactionId)
}

/**
 * Where a transaction is in its lifecycle. Only [CREATED] accepts a wallet response
 * carrying a PRESENTATION: in any other state the nonce has already been spent and the
 * submission is rejected as a replay.
 *
 * Wallet ERROR responses are the documented exception — they are acknowledged whatever the
 * state, because an error grants nothing and OpenID4VP requires the acknowledgement
 * (§8.2). An already recorded outcome is never overwritten by one.
 */
enum class TransactionState { CREATED, PRESENTED, VERIFIED, REJECTED }

/**
 * One in-flight verification.
 *
 * The presentation itself is NEVER stored: it is verified and dropped inside
 * [dev.zilath.verifier.core.CredentialVerifier.verify]. What does live here until the
 * transaction expires is [outcome], and for a success that carries the DISCLOSED CLAIMS —
 * they have to survive somewhere between the wallet's POST and the checkout's poll of
 * [VerificationFlow.awaitOutcome].
 *
 * So this is short-lived, but it is not empty. When the claims leave:
 * - they are never written if the verification finishes after [expiresAt] — the flow then
 *   stores the redaction instead;
 * - no read returns them after [expiresAt], on any store;
 * - they leave the store at the first of: the flow's next call on this transaction after
 *   [expiresAt] (any of them — a poll, with any token; a wallet POST; a request object
 *   fetch; a response code — redacts the entry in place); the store's own redaction or
 *   removal. [InMemoryTransactionStore]
 *   redacts within 30 seconds of [expiresAt] even in an idle process, and removes the entry
 *   a minute later.
 *
 * Anyone plugging in a SHARED store (Redis and the like) is putting those claims on that
 * infrastructure, and must treat it accordingly — encryption at rest, no persistence to disk,
 * no backups.
 */
data class Transaction(
    val id: TransactionId,
    val nonce: String,
    val state: TransactionState,
    val createdAt: Instant,
    /**
     * The last instant the transaction is valid: `createdAt` plus the configuration's
     * [RelyingPartyConfiguration.transactionTimeToLive], fixed by the flow at creation.
     *
     * The ONE clock for this transaction's life — the request object's `exp`, every check
     * the flow makes, and the retention a store applies all read it. The fourth internal
     * review found two: the flow's configuration and the in-memory store's own time to
     * live, set independently, so that a longer one kept claims readable past the documented
     * bound and a shorter one refused holders whose request object was still valid.
     */
    val expiresAt: Instant,
    val request: PresentationRequest,
    /**
     * The hash of the [PollToken] that reads this transaction's outcome (base64url SHA-256):
     * the token itself is never stored, so neither a store nor its backups can read with it.
     */
    val pollTokenHash: String,
    val outcome: FlowOutcome? = null,
    val mode: FlowMode = FlowMode.CROSS_DEVICE,
    /**
     * The hash of the single-use same-device return code (base64url SHA-256), as
     * [pollTokenHash] is of its token: the code itself goes to the wallet and is never
     * stored, so a store and its backups cannot redeem it and take the read right over.
     * Cleared when consumed.
     */
    val responseCodeHash: String? = null,
    /** True once the user-agent came back through the response-code exchange (WP_094). */
    val returned: Boolean = false,
    /**
     * This transaction's own response encryption key, PRIVATE half included: the request
     * object publishes its public half, and the wallet's response is decrypted with it. It
     * leaves the store in the same atomic update that consumes the nonce, when the first
     * wallet response arrives; for a transaction nobody answers, when the claims would (see
     * above): at the flow's next call after [expiresAt], or the store's own redaction or
     * removal — within 30 seconds of [expiresAt] in [InMemoryTransactionStore]. A store that
     * persists transactions persists this key with them, for that time: another reason not
     * to write them to disk or backups.
     */
    val responseEncryptionKey: ECKey? = null,
) {
    /** Whether [now] is strictly after [expiresAt]: the boundary instant itself still counts as valid. */
    fun isExpired(now: Instant): Boolean = expiresAt.isBefore(now)

    /**
     * Never the nonce, the response code or the claims: the first two are bearer secrets for
     * the time to live, the last are the person. A data class prints every property, and the
     * interface invites stores that may log what they hold; the fourth internal review found
     * exactly that, next to key holders whose toString the library already redacted.
     */
    override fun toString(): String =
        "Transaction(id=${id.value}, state=$state, mode=$mode, createdAt=$createdAt, expiresAt=$expiresAt, " +
            "outcome=${outcome?.javaClass?.simpleName}, hasResponseCode=${responseCodeHash != null}, " +
            "returned=$returned)"
}
