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
 * The verifier for [key], or null when the key is not one this library will check a
 * signature with.
 *
 * Nimbus enforces a minimum RSA size only when GENERATING a key: `RSASSAVerifier` accepts
 * a 512-bit modulus, which factors in hours on ordinary hardware, and a signature under it
 * is a signature anyone can make. RFC 7518 §3.3 says a key of 2048 bits or larger MUST be
 * used with the RS and PS algorithms; below that the key is skipped, exactly as a key of
 * an unknown type is. Elliptic curves are limited to the three NIST curves the JOSE
 * algorithms name — the IT-Wallet profile mandates ES256/384/512 — which leaves out
 * secp256k1, a curve Nimbus also verifies.
 *
 * Returning null rather than throwing is deliberate: callers try every trusted key in
 * turn, and an unusable one must count as "does not match", never as an error that stops
 * the search or, worse, as a match.
 */
@InternalZilathApi
fun acceptableJwsVerifierFor(key: JWK): JWSVerifier? =
    when (key.keyType) {
        KeyType.EC -> key.toECKey().takeIf { it.curve in ACCEPTED_CURVES }?.let(::ECDSAVerifier)
        KeyType.RSA -> key.toRSAKey().takeIf { it.size() >= MIN_RSA_KEY_BITS }?.let(::RSASSAVerifier)
        else -> null
    }

/**
 * True when [jwt] verifies under at least one of [keys] that [acceptableJwsVerifierFor]
 * accepts. A key that cannot produce a verifier, or that throws while verifying (an EC key
 * against an RS256 signature, say), simply does not count as a match — so an unusable key
 * can never turn into an accepted signature, nor stop the next key from being tried.
 */
@InternalZilathApi
fun verifiesWithAnyAcceptableKey(
    jwt: SignedJWT,
    keys: List<JWK>,
): Boolean =
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
 * hundred kilobytes per request. A surrogate pair cut by the limit is dropped whole, so the
 * result is always well-formed text.
 */
@InternalZilathApi
fun boundedPrintable(value: String): String {
    val cut =
        value.take(MAX_PRINTABLE_LENGTH).let {
            if (it.lastOrNull()?.isHighSurrogate() ==
                true
            ) {
                it.dropLast(1)
            } else {
                it
            }
        }
    return cut
        .map {
            if (it.isISOControl() ||
                it == LINE_SEPARATOR ||
                it == PARAGRAPH_SEPARATOR
            ) {
                '?'
            } else {
                it
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

/** RFC 7518 §3.3 and §3.5. */
private const val MIN_RSA_KEY_BITS = 2048

private val ACCEPTED_CURVES = setOf(Curve.P_256, Curve.P_384, Curve.P_521)
