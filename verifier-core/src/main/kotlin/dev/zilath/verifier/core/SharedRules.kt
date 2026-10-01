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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jwt.SignedJWT
import java.net.URI
import java.util.Locale

/*
 * Rules every Zilath module must apply the same way. Each one used to live, or not live,
 * in whichever module needed it first; see [InternalZilathApi] for why they are shared.
 */

/**
 * The `alg` values a JWS may carry for this library to verify its signature: the signature
 * algorithms IT-Wallet 1.4.7 lists as MUST (`ES256`, `ES384`, `ES512`) or RECOMMENDED
 * (`PS256`, `PS384`, `PS512`) in its Cryptographic Algorithms section (`algorithms.rst` of
 * the specification), which test ATT-004 turns into a rule for any party that evaluates a
 * signed statement: only the listed algorithms are accepted, "deprecated or unlisted
 * algorithms are rejected".
 *
 * Not on the list, so refused: `RS256`, `RS384` and `RS512`, `ES256K`, and `EdDSA`,
 * `Ed25519` and `Ed448` (the profile requires no Edwards-curve algorithm); and the HMAC
 * algorithms and `none`, which the list gives as MUST NOT. `ESP256`, `ESP384` and `ESP512`
 * are on the list as COSE algorithms (`-9`, `-51`, `-52`), whose JOSE counterparts are
 * `ES256`, `ES384` and `ES512`; this library has no COSE path, and Nimbus 10.3 does not
 * verify under the names either.
 *
 * Every JWS signature the library checks goes through [verifiesWithAnyAcceptableKey], which
 * applies this set: the issuer JWT, the key binding JWT, the status list token and every
 * federation entity statement. A new call site must go through it too.
 */
@InternalZilathApi
val ACCEPTED_JWS_ALGORITHMS: Set<JWSAlgorithm> =
    setOf(
        JWSAlgorithm.ES256,
        JWSAlgorithm.ES384,
        JWSAlgorithm.ES512,
        JWSAlgorithm.PS256,
        JWSAlgorithm.PS384,
        JWSAlgorithm.PS512,
    )

/** Whether a JWS whose header says [algorithm] may have its signature checked: see [ACCEPTED_JWS_ALGORITHMS]. */
@InternalZilathApi
fun isAcceptedJwsAlgorithm(algorithm: JWSAlgorithm?): Boolean =
    algorithm != null && algorithm in ACCEPTED_JWS_ALGORITHMS

/**
 * The verifier for [key], or null when the key is not one this library will check a
 * signature with.
 *
 * Nimbus enforces a minimum RSA size only when GENERATING a key: `RSASSAVerifier` accepts
 * a 512-bit modulus, which factors in hours on ordinary hardware, and a signature under it
 * is a signature anyone can make. RFC 7518 §3.3 makes 2048 bits the floor for the RS and PS
 * algorithms; IT-Wallet 1.4.7 asks for more. Its test ATT-006 wants keys that provide at
 * least 128 bits of security strength as NIST SP 800-57 Part 1 defines it, and for RSA that
 * is a modulus of 3072 bits (Table 2: 2048 bits give 112). Below 3072 the key is skipped,
 * exactly as a key of an unknown type is.
 *
 * Elliptic curves are limited to the three NIST curves the JOSE algorithms name — the
 * IT-Wallet profile mandates ES256/384/512 — which leaves out secp256k1, a curve Nimbus
 * also verifies. P-256 gives 128 bits of security strength, P-384 192 and P-521 256, so none
 * of the three falls under the bar ATT-006 sets, and the algorithms of
 * [ACCEPTED_JWS_ALGORITHMS] reach no other curve.
 *
 * Returning null rather than throwing is deliberate: callers try every trusted key in
 * turn, and an unusable one must count as "does not match", never as an error that stops
 * the search or, worse, as a match.
 */
@InternalZilathApi
fun acceptableJwsVerifierFor(key: JWK): JWSVerifier? =
    when (key.keyType) {
        KeyType.EC -> key.toECKey().takeIf { it.curve in ACCEPTED_CURVES }?.let(::ECDSAVerifier)
        // The bit length of the modulus itself, not RSAKey.size(): that counts the bytes of `n`
        // as encoded, so a modulus padded with leading zero bytes reported the padded length.
        KeyType.RSA ->
            key
                .toRSAKey()
                .takeIf { it.modulus.decodeToBigInteger().bitLength() >= MIN_RSA_KEY_BITS }
                ?.let(::RSASSAVerifier)
        else -> null
    }

/**
 * True when [jwt] is signed with an algorithm of [ACCEPTED_JWS_ALGORITHMS] and verifies
 * under at least one of [keys] that [acceptableJwsVerifierFor] accepts. The algorithm comes
 * first and is not a fallback: a signature that is mathematically valid under a trusted key
 * but made with an unlisted algorithm (`RS256` under a 3072-bit RSA key, say) is refused.
 *
 * A key that cannot produce a verifier, or that throws while verifying (an EC key against
 * a PS256 signature, say), simply does not count as a match — so an unusable key can never
 * turn into an accepted signature, nor stop the next key from being tried.
 */
@InternalZilathApi
fun verifiesWithAnyAcceptableKey(
    jwt: SignedJWT,
    keys: List<JWK>,
): Boolean =
    isAcceptedJwsAlgorithm(jwt.header.algorithm) &&
        keys.any { key ->
            runCatching { acceptableJwsVerifierFor(key)?.let(jwt::verify) == true }.getOrDefault(false)
        }

/**
 * Compares a JOSE `typ` header against the media subtype [expected] (`statuslist+jwt`,
 * `entity-statement+jwt`, `dc+sd-jwt`, ...).
 *
 * RFC 7515 §4.1.9: media type values are case-insensitive, and a recipient MUST treat a
 * `typ` without a `/` as if `application/` were prepended. `application/statuslist+jwt`
 * and `StatusList+JWT` therefore name the same type as `statuslist+jwt`, and an exact
 * string comparison turned genuine documents away. A parameter (`;`) or any other
 * top-level type is still a different type. A null [typ] never matches: whether an
 * ABSENT header is tolerated is each caller's decision, not this function's.
 */
@InternalZilathApi
fun mediaTypeMatches(
    typ: String?,
    expected: String,
): Boolean {
    val subtype = typ?.trim()?.lowercase(Locale.ROOT)?.removePrefix("application/")
    return subtype != null && '/' !in subtype && ';' !in subtype && subtype == expected.lowercase(Locale.ROOT)
}

/**
 * [value] as a URI when it is safe to hand to a fetcher, otherwise null: HTTPS with a
 * non-empty host, no fragment, no userinfo; plain `http` only for the exact localhost
 * names. IP-literal hosts other than loopback are refused too: federation entities and
 * status list issuers live behind names, and a bare address in a signed document is the
 * shape a reach for something internal takes (SSRF). A query string is left to the caller
 * to allow or refuse.
 *
 * What this CANNOT catch is a hostname that resolves to an internal address — the library
 * never resolves names — which is why the network boundary itself belongs to the injected
 * fetcher. Moved here from `verifier-trust-itwallet` by the fourth internal review, which
 * found that the status list URI, documented as held to this rule, never was.
 */
@InternalZilathApi
fun usableHttpsUriOrNull(value: String): URI? {
    val uri = runCatching { URI(value) }.getOrNull() ?: return null
    val host = uri.host
    val usable =
        !host.isNullOrBlank() &&
            uri.userInfo == null &&
            uri.fragment == null &&
            (host in LOCALHOST_HOSTS || !isIpLiteral(host)) &&
            (uri.scheme == "https" || (uri.scheme == "http" && host in LOCALHOST_HOSTS))
    return if (usable) uri else null
}

/**
 * [value] made safe to put in a log line or a `detail` it may end up in: at most
 * [MAX_PRINTABLE_LENGTH] characters, and every ISO control character — CR, LF, NUL, ESC,
 * NEL among them — and the Unicode line and paragraph separators replaced with `?`.
 *
 * For text the library does not write itself: a [TrustEvaluator]'s reason, a wallet's error
 * string. The fourth internal review forged whole log lines through a credential's `iss`
 * that reached a rejection's `detail` with its CRLF intact, and flooded the log with a
 * hundred kilobytes per request. A surrogate pair cut by the limit is dropped whole, and a
 * surrogate that was unpaired in [value] already becomes `?` too, so the result is always
 * well-formed text.
 */
@InternalZilathApi
fun boundedPrintable(value: String): String {
    // Drop the last character only when the cut itself split a valid pair; a high surrogate
    // that was unpaired already is kept, to become `?` below like any other.
    val splitPair =
        value.length > MAX_PRINTABLE_LENGTH &&
            value[MAX_PRINTABLE_LENGTH - 1].isHighSurrogate() &&
            value[MAX_PRINTABLE_LENGTH].isLowSurrogate()
    val cut = value.take(MAX_PRINTABLE_LENGTH).let { if (splitPair) it.dropLast(1) else it }
    return cut
        .mapIndexed { index, char ->
            when {
                char.isISOControl() || char == LINE_SEPARATOR || char == PARAGRAPH_SEPARATOR -> '?'
                char.isHighSurrogate() && cut.getOrNull(index + 1)?.isLowSurrogate() != true -> '?'
                char.isLowSurrogate() && cut.getOrNull(index - 1)?.isHighSurrogate() != true -> '?'
                else -> char
            }
        }.joinToString("")
}

/** Long enough for any diagnostic phrase, too short to flood a log. */
private const val MAX_PRINTABLE_LENGTH = 200

private const val LINE_SEPARATOR = '\u2028'
private const val PARAGRAPH_SEPARATOR = '\u2029'

/**
 * Bracketed IPv6, or anything made only of digits and dots.
 *
 * Not only the dotted quad. The JVM's resolver reads `2130706433` as 127.0.0.1 and
 * `2851995650` as 169.254.0.2, and `0177.0.0.1` has four digits where a quad pattern allowed
 * three: every one of those passed the earlier check as a "hostname" and reached the fetcher
 * (third review, reproduced against `InetAddress`). No valid hostname consists solely of
 * digits and dots — RFC 1123 §2.1, the top-level label is never all-numeric — so refusing
 * the whole class costs no legitimate entity.
 */
private fun isIpLiteral(host: String): Boolean = host.startsWith("[") || NUMERIC_HOST.matches(host)

private val NUMERIC_HOST = Regex("""[0-9.]+""")

private val LOCALHOST_HOSTS = setOf("localhost", "127.0.0.1", "[::1]", "::1")

/**
 * 128 bits of security strength, which IT-Wallet 1.4.7 asks of keys in test ATT-006: NIST SP 800-57
 * Part 1, Table 2. RFC 7518 §3.3 and §3.5 alone would allow 2048.
 */
private const val MIN_RSA_KEY_BITS = 3072

private val ACCEPTED_CURVES = setOf(Curve.P_256, Curve.P_384, Curve.P_521)
