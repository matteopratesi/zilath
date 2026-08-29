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
package dev.zilath.verifier.core

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.SignedJWT
import java.time.Clock
import java.time.Duration
import java.util.zip.Inflater

/**
 * True when [jwt] verifies under at least one of [keys]. A key that cannot produce a
 * verifier, or that throws while verifying, simply does not count as a match — so an
 * unusable key can never turn into an accepted signature.
 */
private fun verifiesWithAny(
    jwt: SignedJWT,
    keys: List<JWK>,
): Boolean =
    keys.any { key ->
        runCatching { jwsVerifierFor(key)?.let(jwt::verify) == true }.getOrDefault(false)
    }

/** Retrieves a status list token from its URI; injectable so tests stay offline. */
fun interface StatusListFetcher {
    /**
     * Returns the raw status list token served at [uri], or throws on any transport error.
     *
     * Throwing is correct here: [OAuthStatusListChecker] catches it and degrades to
     * [CredentialStatus.UNKNOWN]. Implementations should set aggressive timeouts — the URI
     * comes from the credential, so a slow endpoint would otherwise stall a checkout.
     */
    fun fetch(uri: String): String
}

/**
 * [StatusChecker] backed by an OAuth Status List token (draft-ietf-oauth-status-list):
 * a JWT whose `status_list` claim carries a zlib-compressed bit array where each
 * credential occupies `bits` bits at its `idx` position; 0 means valid.
 *
 * The token is validated before it is believed, following §8.3 of the draft: the `typ`
 * header, the signature against keys already trusted for the credential's issuer, `sub`
 * against the URI the credential pointed at, and `exp` if present. Any failure at any step
 * — transport, parsing, signature, or a claim that does not match — degrades to
 * [CredentialStatus.UNKNOWN], never to valid, and the inflated list is size-capped against
 * a zip bomb.
 *
 * **Third-party status issuers are not supported.** The draft allows the Status Issuer to
 * be a different entity from the credential's Issuer (§11.3) but mandates no way to
 * establish trust in it, so this implementation accepts only a status list signed by the
 * issuer of the credential being checked. A token from anyone else is [CredentialStatus.UNKNOWN]
 * — the conservative reading, and the one that cannot be talked into accepting a revoked
 * credential. Supporting a separate status issuer is a policy decision that needs
 * configuration, not a default.
 */
class OAuthStatusListChecker(
    private val fetcher: StatusListFetcher,
    private val clock: Clock = Clock.systemUTC(),
    private val maxAge: Duration = DEFAULT_MAX_AGE,
) : StatusChecker {
    override fun check(
        statusRef: StatusReference,
        trust: StatusIssuerTrust,
    ): CredentialStatus = runCatching { lookup(statusRef, trust) }.getOrDefault(CredentialStatus.UNKNOWN)

    private fun lookup(
        statusRef: StatusReference,
        trust: StatusIssuerTrust,
    ): CredentialStatus {
        val token = fetcher.fetch(statusRef.uri)
        val jwt = SignedJWT.parse(token)
        validate(jwt, statusRef, trust)
        val statusList =
            checkNotNull(jwt.jwtClaimsSet.getJSONObjectClaim("status_list")) {
                "token has no status_list claim"
            }
        val bits = (statusList["bits"] as Number).toInt()
        require(bits in VALID_BITS_SIZES) { "unsupported bits size: $bits" }
        val compressed = Base64URL.from(statusList["lst"] as String).decode()
        val value = statusValueAt(inflate(compressed), bits, statusRef.index)
        return if (value == 0) CredentialStatus.VALID else CredentialStatus.REVOKED
    }

    /**
     * The checks of draft-ietf-oauth-status-list §8.3 that stand between a fetched
     * document and a statement about someone's credential. Each one throws, and [check]
     * turns any throw into [CredentialStatus.UNKNOWN]: there is deliberately no path
     * through this function that ends in VALID without all of them having passed.
     */
    private fun validate(
        jwt: SignedJWT,
        statusRef: StatusReference,
        trust: StatusIssuerTrust,
    ) {
        require(jwt.header.type?.toString() == STATUS_LIST_TYP) {
            "status list token typ is not $STATUS_LIST_TYP"
        }
        val claims = jwt.jwtClaimsSet
        // Only the issuer of the credential may speak about that credential's status. The
        // draft permits a separate status issuer but gives no way to trust one, and the
        // keys below are the ONLY keys we have any reason to believe.
        val issuer = trust.issuer
        require(!issuer.isNullOrBlank() && claims.issuer == issuer) {
            "status list is not issued by the credential's issuer"
        }
        require(trust.issuerKeys.isNotEmpty()) { "no trusted keys for the status list issuer" }
        require(verifiesWithAny(jwt, trust.issuerKeys)) { "status list token signature does not verify" }
        // sub binds the token to the URI the credential pointed at, so a valid token for a
        // different list cannot be replayed in place of this one.
        require(claims.subject == statusRef.uri) { "status list sub does not match the referenced uri" }
        val now = clock.instant()
        claims.expirationTime?.let { expiry ->
            // Strictly before, per RFC 7519 §4.1.4, and matching how the credential's own
            // exp is treated in SdJwtVcCredentialVerifier: two temporal checks in the same
            // pipeline disagreeing on the boundary instant is a bug waiting for a clock.
            require(now.isBefore(expiry.toInstant())) { "status list token is expired" }
        }
        // exp is only RECOMMENDED by the draft (§5.1), so a compliant token may carry none
        // and would then never go stale: an attacker who captured a genuine "nobody is
        // revoked" list could replay it forever. iat is REQUIRED, and §8.3 step 4b points
        // at exactly this — a relying-party freshness policy on iat. Refusing tokens
        // without exp would have been the other way to close it, at the cost of failing
        // spec-compliant issuers, and every one of those failures is a denied entitlement.
        val issuedAt =
            requireNotNull(claims.issueTime?.toInstant()) { "status list token has no iat" }
        require(!issuedAt.isAfter(now.plus(CLOCK_SKEW))) { "status list token is issued in the future" }
        require(!issuedAt.isBefore(now.minus(maxAge))) { "status list token older than $maxAge" }
    }

    private fun statusValueAt(
        bytes: ByteArray,
        bits: Int,
        index: Int,
    ): Int {
        val entriesPerByte = BITS_PER_BYTE / bits
        val byteIndex = index / entriesPerByte
        require(byteIndex in bytes.indices) { "index $index outside the status list" }
        val shift = (index % entriesPerByte) * bits
        val mask = (1 shl bits) - 1
        return (bytes[byteIndex].toInt() shr shift) and mask
    }

    private fun inflate(compressed: ByteArray): ByteArray {
        val inflater = Inflater()
        return try {
            inflater.setInput(compressed)
            val buffer = ByteArray(INFLATE_BUFFER_SIZE)
            val output = java.io.ByteArrayOutputStream()
            while (!inflater.finished()) {
                val produced = inflater.inflate(buffer)
                check(produced > 0 || inflater.finished()) { "truncated status list" }
                output.write(buffer, 0, produced)
                // The token comes from a remote, not-yet-trusted source: cap the expansion
                // so a small zlib payload cannot exhaust the heap (zip bomb).
                check(output.size() <= MAX_INFLATED_SIZE) { "status list larger than $MAX_INFLATED_SIZE bytes" }
            }
            output.toByteArray()
        } finally {
            inflater.end()
        }
    }

    companion object {
        /** draft-ietf-oauth-status-list §5.1: the JWT type MUST be this. */
        private const val STATUS_LIST_TYP = "statuslist+jwt"

        /**
         * How stale a status list may be before it stops counting as an answer. The draft
         * sets no number — it is a relying-party policy (§8.3 step 4b) — so this is a
         * choice, not a rule: a day bounds the replay window for a token with no `exp`
         * while tolerating issuers that republish daily. Tighten it if your issuer
         * refreshes more often; every hour you cut is an hour a revocation takes to bite.
         */
        val DEFAULT_MAX_AGE: Duration = Duration.ofDays(1)

        /** Tolerance for a status issuer's clock running slightly ahead of ours. */
        private val CLOCK_SKEW: Duration = Duration.ofMinutes(1)

        private const val BITS_PER_BYTE = 8
        private const val INFLATE_BUFFER_SIZE = 4096

        /** 1 MiB holds 8.4M single-bit entries: far above any realistic status list. */
        private const val MAX_INFLATED_SIZE = 1 shl 20
        private val VALID_BITS_SIZES = setOf(1, 2, 4, 8)
    }
}
