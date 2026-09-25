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

/** True when [jwt] verifies under at least one of [keys]: see [verifiesWithAnyAcceptableKey]. */
@OptIn(InternalZilathApi::class)
private fun verifiesWithAny(
    jwt: SignedJWT,
    keys: List<JWK>,
): Boolean = verifiesWithAnyAcceptableKey(jwt, keys)

/** Retrieves a status list token from its URI; injectable so tests stay offline. */
fun interface StatusListFetcher {
    /**
     * Returns the raw status list token served at [uri], or throws on any transport error.
     *
     * Throwing is correct here: [OAuthStatusListChecker] catches it and degrades to
     * [CredentialStatus.UNKNOWN]. Implementations should set aggressive timeouts — the URI
     * comes from the credential, so a slow endpoint would otherwise stall a checkout.
     *
     * SECURITY: the URI is asserted by the credential's issuer — an entity trusted for
     * signatures, not for network destinations. The library hands over only a URI that
     * passes [usableHttpsUriOrNull] (https with a hostname, plain http only for localhost,
     * no userinfo, no fragment, no IP literal other than loopback), but it never resolves
     * names, so a hostname pointing inside your network still reaches you. Treat it as remote input: cap the response
     * size, refuse or re-validate redirects, and refuse destinations inside a network the
     * deployment must protect.
     */
    fun fetch(uri: String): String
}

/**
 * [StatusChecker] backed by an OAuth Status List token (draft-ietf-oauth-status-list):
 * a JWT whose `status_list` claim carries a zlib-compressed array where each credential
 * occupies `bits` bits at its `idx` position.
 *
 * The token is validated before it is believed, following §8.3 of the draft. Exactly these
 * checks, all of them before a single bit is read:
 * - the reference's `uri` is a usable https URL ([usableHttpsUriOrNull]), before the fetcher
 *   is called at all;
 * - the `typ` header is `statuslist+jwt`, compared as RFC 7515 §4.1.9 says ([mediaTypeMatches]);
 * - the signature verifies under one of [StatusIssuerTrust.issuerKeys], the keys already
 *   trusted for the credential's issuer;
 * - `iss`, when the token carries one, equals the credential's issuer. Its absence is not a
 *   failure: neither the draft (§5.1) nor IT-Wallet 1.4.6 (§11.4.4.1.1) requires it, and
 *   both examples omit it. The signature above already binds the token to that issuer;
 * - `sub` equals the `uri` the credential pointed at;
 * - `exp`, when present, is strictly in the future;
 * - `iat` is present, at most a minute ahead of our clock and not older than `maxAge`.
 *
 * Any failure at any step — transport, parsing, signature, or a claim that does not match —
 * degrades to [CredentialStatus.UNKNOWN], never to valid, and both the token and the
 * inflated list are size-capped (see `maxInflatedBytes`).
 *
 * The value read maps as the draft's Status Types (§7.1) do: 0x00 [CredentialStatus.VALID],
 * 0x01 [CredentialStatus.REVOKED], 0x02 [CredentialStatus.SUSPENDED], anything else
 * [CredentialStatus.APPLICATION_SPECIFIC] — IT-Wallet's UPDATE (0x03) and ATTRIBUTE_UPDATE
 * (0x0F) among them. Only 0x00 lets a verification succeed.
 *
 * **Third-party status issuers are not supported.** The draft allows the Status Issuer to
 * be a different entity from the credential's Issuer (§11.3) but mandates no way to
 * establish trust in it, so this implementation accepts only a status list signed by the
 * issuer of the credential being checked. A token from anyone else is [CredentialStatus.UNKNOWN]
 * — the conservative reading, and the one that cannot be talked into accepting a revoked
 * credential. Supporting a separate status issuer is a policy decision that needs
 * configuration, not a default.
 *
 * @param maxInflatedBytes the largest decompressed list this checker will hold in memory;
 *   see [DEFAULT_MAX_INFLATED_BYTES] for what it means in entries.
 */
@OptIn(InternalZilathApi::class)
class OAuthStatusListChecker(
    private val fetcher: StatusListFetcher,
    private val clock: Clock = Clock.systemUTC(),
    private val maxAge: Duration = DEFAULT_MAX_AGE,
    private val maxInflatedBytes: Int = DEFAULT_MAX_INFLATED_BYTES,
) : StatusChecker {
    init {
        require(maxInflatedBytes > 0) { "maxInflatedBytes must be positive" }
    }

    override fun check(
        statusRef: StatusReference,
        trust: StatusIssuerTrust,
    ): CredentialStatus = runCatching { lookup(statusRef, trust) }.getOrDefault(CredentialStatus.UNKNOWN)

    private fun lookup(
        statusRef: StatusReference,
        trust: StatusIssuerTrust,
    ): CredentialStatus {
        // The credential's issuer chose this URI: an entity trusted for signatures, not for
        // network destinations. The verifier already refuses a credential whose URI fails
        // the rule, so this guards a caller that builds a StatusReference by hand — before
        // the fetcher sees it, not after (SECURITY.md B1). A query string is legal here.
        requireNotNull(usableHttpsUriOrNull(statusRef.uri)) { "status list uri is not a usable https url" }
        val token = fetcher.fetch(statusRef.uri)
        // Checked before parsing, for the same reason the inflated size is: the token comes
        // from a remote source that is not trusted yet. A legitimate token cannot be longer:
        // its payload base64url-encodes `lst`, which is itself base64url, so the compressed
        // list appears at 16/9 of its size — and a list that compresses at all is smaller
        // than its inflated form. The allowance covers the header (Nimbus refuses more than
        // 20,000 characters there anyway), the other claims and the signature.
        require(token.length.toLong() <= maxInflatedBytes.toLong() * 2 + TOKEN_OVERHEAD_ALLOWANCE) {
            "status list token too long"
        }
        val jwt = SignedJWT.parse(token)
        validate(jwt, statusRef, trust)
        val statusList =
            checkNotNull(jwt.jwtClaimsSet.getJSONObjectClaim("status_list")) {
                "token has no status_list claim"
            }
        val bits = (statusList["bits"] as Number).toInt()
        require(bits in VALID_BITS_SIZES) { "unsupported bits size: $bits" }
        val compressed = Base64URL.from(statusList["lst"] as String).decode()
        return when (statusValueAt(inflate(compressed), bits, statusRef.index)) {
            STATUS_VALID -> CredentialStatus.VALID
            STATUS_INVALID -> CredentialStatus.REVOKED
            STATUS_SUSPENDED -> CredentialStatus.SUSPENDED
            else -> CredentialStatus.APPLICATION_SPECIFIC
        }
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
        require(typIsStatusList(jwt)) {
            "status list token typ is not $STATUS_LIST_TYP"
        }
        val claims = jwt.jwtClaimsSet
        // Only the issuer of the credential may speak about that credential's status. The
        // draft permits a separate status issuer but gives no way to trust one, and the
        // keys below are the ONLY keys we have any reason to believe. A token that names an
        // issuer must name that one; a token that names none is still bound to it by the
        // signature. Before the fourth internal review a missing iss was a failure, which
        // turned every token shaped like the IT-Wallet 1.4.6 example into a denial.
        val issuer = trust.issuer
        require(!issuer.isNullOrBlank()) { "the credential names no issuer" }
        claims.issuer?.let { require(it == issuer) { "status list is not issued by the credential's issuer" } }
        require(trust.issuerKeys.isNotEmpty()) { "no trusted keys for the status list issuer" }
        require(verifiesWithAny(jwt, trust.issuerKeys)) { "status list token signature does not verify" }
        // sub binds the token to the URI the credential pointed at, so a valid token for a
        // different list cannot be replayed in place of this one.
        require(claims.subject == statusRef.uri) { "status list sub does not match the referenced uri" }
        val now = clock.instant()
        // Both dates read as numbers from the payload, never through Nimbus's Date, whose
        // seconds-to-milliseconds conversion wraps around: see numericDateClaim.
        val payload = jwt.payload.toJSONObject()
        when (val exp = numericDateClaim(payload, "exp")) {
            NumericDateClaim.Absent -> Unit
            NumericDateClaim.Invalid -> throw IllegalArgumentException("status list exp is not a plausible date")
            // Strictly before, per RFC 7519 §4.1.4, and deliberately WITHOUT the minute of
            // tolerance the credential's own exp gets in SdJwtVcCredentialVerifier: a stale
            // status list is refetched, a stale credential is turned away — the asymmetry is
            // the point. (The third review found this comment still claiming parity.)
            is NumericDateClaim.At -> require(now.isBefore(exp.instant)) { "status list token is expired" }
        }
        // exp is only RECOMMENDED by the draft (§5.1), so a compliant token may carry none
        // and would then never go stale: an attacker who captured a genuine "nobody is
        // revoked" list could replay it forever. iat is REQUIRED, and §8.3 step 4b points
        // at exactly this — a relying-party freshness policy on iat. Refusing tokens
        // without exp would have been the other way to close it, at the cost of failing
        // spec-compliant issuers, and every one of those failures is a denied entitlement.
        val issuedAt =
            requireNotNull((numericDateClaim(payload, "iat") as? NumericDateClaim.At)?.instant) {
                "status list token has no plausible iat"
            }
        require(!issuedAt.isAfter(now.plus(CLOCK_SKEW))) { "status list token is issued in the future" }
        require(!issuedAt.isBefore(now.minus(maxAge))) { "status list token older than $maxAge" }
    }

    /** RFC 7515 §4.1.9 equivalence, not string equality: see [mediaTypeMatches]. */
    private fun typIsStatusList(jwt: SignedJWT): Boolean =
        mediaTypeMatches(jwt.header.type?.toString(), STATUS_LIST_TYP)

    private fun statusValueAt(
        bytes: ByteArray,
        bits: Int,
        index: Int,
    ): Int {
        // A negative index passes the byteIndex bounds check below — -1/8 is 0 — and then
        // shifts by a negative amount, which the JVM masks to (n and 31): the read silently
        // lands on a different credential's entry. Refuse it outright.
        require(index >= 0) { "negative status list index" }
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
                check(output.size() <= maxInflatedBytes) { "status list larger than the configured cap" }
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

        /**
         * 16 MiB of inflated list: 134,217,728 entries at `bits` 1, 67,108,864 at 2,
         * 33,554,432 at 4 and 16,777,216 at 8. The cap is a bound on memory, and what it
         * means for an issuer depends on `bits`: IT-Wallet needs at least 2 to say
         * SUSPENDED and 4 for UPDATE and ATTRIBUTE_UPDATE, and the draft's own size
         * discussion (§13.4) reasons about lists of 10 and 100 million entries, which
         * issuers are asked to build for herd privacy. The fourth internal review found the
         * earlier 1 MiB — "8.4M single-bit entries" in its comment — holding barely a
         * million entries at `bits` 8, and every lookup in a larger list ending UNKNOWN.
         * A list is decompressed once per verification and dropped; lower the cap through
         * the constructor if the heap is tight, never below what your issuer publishes.
         */
        const val DEFAULT_MAX_INFLATED_BYTES: Int = 16 shl 20

        /** Header, claims other than `status_list`, and signature of a status list token. */
        private const val TOKEN_OVERHEAD_ALLOWANCE = 64L * 1024

        /** draft-ietf-oauth-status-list §7.1 Status Types. */
        private const val STATUS_VALID = 0x00
        private const val STATUS_INVALID = 0x01
        private const val STATUS_SUSPENDED = 0x02

        private const val BITS_PER_BYTE = 8
        private const val INFLATE_BUFFER_SIZE = 4096
        private val VALID_BITS_SIZES = setOf(1, 2, 4, 8)
    }
}
