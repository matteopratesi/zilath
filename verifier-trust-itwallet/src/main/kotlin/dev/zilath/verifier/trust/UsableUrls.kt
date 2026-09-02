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
package dev.zilath.verifier.trust

/*
 * The shape rules for every URL the online trust-chain walk is willing to dereference.
 * Everything here runs on attacker-influenced strings — the `iss` of an unverified
 * credential, `authority_hints`, `federation_fetch_endpoint` — BEFORE they reach the
 * integrator's [FederationFetcher].
 */

/**
 * An entity identifier must be an HTTPS URL with a host, no query and no fragment — plain
 * `http` only for the exact localhost names, as [RpFederationConfig] already requires of our
 * own.
 *
 * This runs BEFORE the first fetch, and the identifier at that point is the `iss` of a
 * credential nobody has verified yet. Without it the library would hand an arbitrary
 * attacker-chosen string — `file:`, `http://10.0.0.1:8080`, anything — to the integrator's
 * fetcher and ask it to dereference it.
 */
internal fun requireUsableEntityId(entityId: String) {
    val uri = usableFetchUrlOrNull(entityId)
    if (uri == null || uri.query != null) {
        trustFail("entity id is not a usable https identifier: $entityId")
    }
}

/**
 * A `federation_fetch_endpoint` obeys the same shape rules as an entity id, except that a
 * query string is legal — `sub` is appended to whatever the endpoint already carries.
 *
 * The value comes from the still-unverified configuration of a superior (nothing in the
 * online walk is trusted until the chain closes at the anchor), so it must not reach the
 * fetcher unchecked: anyone able to serve one federation document could otherwise point
 * the integrator's HTTP client at `file:`, at an internal address, at anything.
 */
internal fun requireUsableFetchEndpoint(
    endpoint: String,
    superior: String,
) {
    if (usableFetchUrlOrNull(endpoint) == null) {
        trustFail("federation_fetch_endpoint of $superior is not a usable https url")
    }
}

/**
 * HTTPS with a non-empty host, no fragment, no userinfo; plain `http` only for the exact
 * localhost names. IP-literal hosts other than loopback are refused too: federation
 * entities live behind names, and a bare address in a chain document is the shape a reach
 * for something internal takes (SSRF). What this CANNOT catch is a hostname that resolves
 * to an internal address — the library never resolves names — which is why the network
 * boundary itself belongs to the [FederationFetcher] implementation.
 */
private fun usableFetchUrlOrNull(value: String): java.net.URI? {
    val uri = runCatching { java.net.URI(value) }.getOrNull() ?: return null
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
