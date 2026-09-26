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

import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.InternalZilathApi
import dev.zilath.verifier.core.mediaTypeMatches
import java.time.Duration
import java.time.Instant
import java.util.concurrent.atomic.AtomicReference

/**
 * Supplies the RP's current trust chain for the request object's `trust_chain` header —
 * its own entity configuration first, then the statements up to the trust anchor — so
 * that a chain renewed before it expires (IT-Wallet 1.4.6 §6.11.2, fast renewal) reaches
 * wallets without a restart. Called for every request object; keep it cheap (cache what
 * the federation serves, refresh it ahead of the earliest `exp`).
 */
fun interface TrustChainSource {
    fun currentTrustChain(): List<String>
}

/**
 * The trust chain to put in a request object built at [now], or null for none.
 *
 * Never an expired one. The statements of a real federation live a day (the IT-Wallet
 * anchor's: exactly 24 hours), and a chain fixed in configuration used to be sent as it
 * stood, so after a day every request object told the wallet to trust a chain that OpenID
 * Federation says not to use ("verify that exp has a value that is in the future"). Now a
 * chain whose earliest `exp` is less than [EXPIRY_MARGIN] away is left out — the wallet
 * then resolves the RP online — and the omission is logged once per chain.
 */
internal fun trustChainHeaderFor(
    federation: RpFederationConfig,
    now: Instant,
): List<String>? {
    val chain =
        federation.trustChainSource?.let { source ->
            runCatching { source.currentTrustChain() }
                .onFailure { warnOnce(emptyList(), "the trust chain source failed (${it.javaClass.name})") }
                .getOrNull()
        } ?: federation.trustChain
    if (chain.isEmpty()) return null
    val expiresAt = runCatching { trustChainExpiryOf(chain, federation.entityId) }.getOrNull()
    return when {
        expiresAt == null -> null.also { warnOnce(chain, "the trust chain is not a valid chain for this RP") }
        !now.plus(EXPIRY_MARGIN).isBefore(expiresAt) -> null.also { warnOnce(chain, "the trust chain has expired") }
        else -> chain
    }
}

/**
 * Checks the shape of [chain] as a chain for [entityId] and returns when it expires: the
 * earliest `exp` of its statements (OpenID Federation §10.4). Every element an entity
 * statement, the first this RP's own entity configuration, each one's `sub` the `iss` of
 * the one before. Signatures are the wallet's to verify; a chain that is not even shaped
 * like this one's is a configuration error.
 */
@OptIn(InternalZilathApi::class)
internal fun trustChainExpiryOf(
    chain: List<String>,
    entityId: String,
): Instant {
    val statements =
        chain.map { element ->
            val jwt =
                requireNotNull(
                    runCatching { SignedJWT.parse(element) }.getOrNull(),
                ) { "a trust chain element is not a signed JWT" }
            require(mediaTypeMatches(jwt.header.type?.toString(), RpEntityConfiguration.ENTITY_STATEMENT_TYP)) {
                "a trust chain element is not an entity statement"
            }
            requireNotNull(
                runCatching { jwt.jwtClaimsSet }.getOrNull(),
            ) { "a trust chain element has unreadable claims" }
        }
    val leaf = statements.first()
    require(leaf.issuer == entityId && leaf.subject == entityId) {
        "the trust chain must start with this RP's own entity configuration"
    }
    statements.zipWithNext().forEach { (lower, upper) ->
        require(upper.subject == lower.issuer) { "the trust chain statements are not linked by iss and sub" }
    }
    return statements.minOf { requireNotNull(it.expirationTime) { "a trust chain statement has no exp" }.toInstant() }
}

/**
 * The same minute of clock tolerance the verifier grants issuers and statements: a chain
 * that expires within it could reach the wallet already expired.
 */
private val EXPIRY_MARGIN: Duration = Duration.ofMinutes(1)

private val logger = System.getLogger(TrustChainSource::class.java.name)

/** The chain last warned about, so an unusable chain is logged once, not per request object. */
private val lastWarned = AtomicReference<List<String>?>()

private fun warnOnce(
    chain: List<String>,
    message: String,
) {
    if (lastWarned.getAndSet(chain) != chain) {
        logger.log(System.Logger.Level.WARNING, "$message: request objects are sent without trust_chain")
    }
}
