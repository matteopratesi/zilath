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
import java.time.Instant
import java.util.concurrent.atomic.AtomicReference

/**
 * A trust mark issued to the relying party (OpenID Federation 1.0 §7), as its issuer returned
 * it at onboarding: a JWT typed `trust-mark+jwt`, with the `kid` of its signing key, naming
 * its issuer (`iss`), the relying party (`sub`), its type (`trust_mark_type`), when it was
 * issued (`iat`) and when it expires (`exp`, which OpenID Federation leaves optional and
 * IT-Wallet 1.4.6 requires, table 8.7).
 */
data class RpTrustMark(
    /**
     * The trust mark type identifier, which the anchor lists in its `trust_mark_issuers`: for a
     * relying party of the production IT-Wallet federation,
     * `https://ta.wallet.ipzs.it/trust_marks/federation-entity/openid_credential_verifier`.
     */
    val type: String,
    /** The signed trust mark, a compact JWT. */
    val jwt: String,
)

/**
 * Supplies the relying party's current trust marks for its entity configuration, so that a
 * mark renewed before it expires reaches wallets without a restart. Called for every entity
 * configuration built; keep it cheap.
 */
fun interface TrustMarkSource {
    fun currentTrustMarks(): List<RpTrustMark>
}

/**
 * The trust marks to publish in an entity configuration built at [now]: the source's, or the
 * configured ones. Never one that has expired, nor, from a source, one that is not this
 * relying party's: a wallet must reject either, so it is left out, and logged once.
 */
internal fun trustMarksToPublish(
    federation: RpFederationConfig,
    now: Instant,
): List<RpTrustMark> {
    val marks =
        federation.trustMarkSource?.let { source ->
            runCatching { source.currentTrustMarks() }
                .onFailure { warnOnce("the trust mark source failed (${it.javaClass.name})") }
                .getOrNull()
        } ?: federation.trustMarks
    return marks.filter { mark ->
        val expiresAt = runCatching { trustMarkExpiryOf(mark, federation.entityId) }.getOrNull()
        when {
            expiresAt == null ->
                false.also {
                    warnOnce(
                        "a trust mark of type ${mark.type} is not a valid mark for this RP",
                    )
                }
            !now.isBefore(expiresAt) -> false.also { warnOnce("the trust mark of type ${mark.type} has expired") }
            else -> true
        }
    }
}

/**
 * Checks [mark] for the shape a wallet checks (OpenID Federation 1.0 §7.1 and §7.3, IT-Wallet
 * 1.4.6 table 8.7) and returns when it expires. Its signature is the wallet's to verify: the
 * relying party does not hold the issuer's keys.
 */
@OptIn(InternalZilathApi::class)
internal fun trustMarkExpiryOf(
    mark: RpTrustMark,
    entityId: String,
): Instant {
    require(mark.type.isNotBlank()) { "a trust mark needs its type" }
    val jwt =
        requireNotNull(
            runCatching { SignedJWT.parse(mark.jwt) }.getOrNull(),
        ) { "trust mark ${mark.type} is not a signed JWT" }
    require(mediaTypeMatches(jwt.header.type?.toString(), TRUST_MARK_TYP)) {
        "trust mark ${mark.type} is not typed $TRUST_MARK_TYP"
    }
    require(!jwt.header.keyID.isNullOrBlank()) { "trust mark ${mark.type} names no signing key (kid)" }
    val claims =
        requireNotNull(runCatching { jwt.jwtClaimsSet }.getOrNull()) { "trust mark ${mark.type} has unreadable claims" }
    require(claims.getClaim("trust_mark_type") == mark.type) {
        "trust mark ${mark.type}: its trust_mark_type claim names another type"
    }
    require(claims.subject == entityId) { "trust mark ${mark.type} was issued to another entity" }
    require(!claims.issuer.isNullOrBlank()) { "trust mark ${mark.type} names no issuer" }
    requireNotNull(claims.issueTime) { "trust mark ${mark.type} has no iat" }
    return requireNotNull(claims.expirationTime) { "trust mark ${mark.type} has no exp" }.toInstant()
}

private const val TRUST_MARK_TYP = "trust-mark+jwt"

private val logger = System.getLogger(TrustMarkSource::class.java.name)

/** The message last logged, so an unusable mark is logged once, not per entity configuration. */
private val lastWarned = AtomicReference<String?>()

private fun warnOnce(message: String) {
    if (lastWarned.getAndSet(message) != message) {
        logger.log(System.Logger.Level.WARNING, "$message: it is left out of the entity configuration")
    }
}
