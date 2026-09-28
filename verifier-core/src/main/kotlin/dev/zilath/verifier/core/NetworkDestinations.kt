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

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * Whether a fetcher of remote documents may connect to [address] under [destinations]: a
 * globally routable unicast address, a loopback one, or either.
 *
 * Loopback is 127.0.0.0/8 and ::1. Globally routable is what follows.
 *
 * For IPv4, every block of the IANA special-purpose registry that is not globally reachable
 * is refused — "this network", the private ranges of RFC 1918, the shared range carriers
 * put behind NAT, loopback, link-local (where cloud metadata services answer), the IETF
 * protocol assignments, the three documentation ranges, the retired 6to4 relay, benchmarking
 * — and so are multicast and the reserved 240/4 with the broadcast address.
 *
 * For IPv6 only global unicast (2000::/3) is accepted, less the IETF protocol block
 * (2001::/23, Teredo among it), the documentation prefixes and 6to4 (2002::/16), which
 * carries an IPv4 address inside. That leaves out loopback, unique local, link-local,
 * multicast and the rest. The one exception is NAT64's well-known prefix (64:ff9b::/96),
 * which an IPv6-only network uses to reach IPv4 hosts: it is accepted when the IPv4 address
 * it carries would be. An IPv4-mapped address needs no rule of its own: the JVM hands it
 * over as the IPv4 address it maps.
 */
internal fun isReachableDestination(
    address: InetAddress,
    destinations: HttpDocumentFetcher.Destinations,
): Boolean =
    when (destinations) {
        HttpDocumentFetcher.Destinations.PUBLIC -> isGloballyRoutable(address)
        HttpDocumentFetcher.Destinations.PUBLIC_AND_LOOPBACK -> address.isLoopbackAddress || isGloballyRoutable(address)
        HttpDocumentFetcher.Destinations.LOOPBACK -> address.isLoopbackAddress
    }

private fun isGloballyRoutable(address: InetAddress): Boolean =
    when (address) {
        is Inet4Address -> isGloballyRoutableV4(address.address)
        is Inet6Address -> isGloballyRoutableV6(address.address)
        else -> false
    }

private fun isGloballyRoutableV4(address: ByteArray): Boolean = V4_REFUSED.none { it.contains(address) }

private fun isGloballyRoutableV6(address: ByteArray): Boolean =
    if (NAT64.contains(address)) {
        isGloballyRoutableV4(address.copyOfRange(NAT64_V4_OFFSET, address.size))
    } else {
        V6_GLOBAL_UNICAST.contains(address) && V6_REFUSED.none { it.contains(address) }
    }

/** An address block in CIDR notation: [prefix] and the number of leading bits that count. */
private class AddressBlock(
    cidr: String,
) {
    private val prefix: ByteArray = InetAddress.getByName(cidr.substringBefore('/')).address
    private val length: Int = cidr.substringAfter('/').toInt()

    fun contains(address: ByteArray): Boolean =
        address.size == prefix.size && (0 until length).all { bit -> address.bitAt(bit) == prefix.bitAt(bit) }
}

private fun ByteArray.bitAt(index: Int): Int =
    (this[index / Byte.SIZE_BITS].toInt() shr (Byte.SIZE_BITS - 1 - index % Byte.SIZE_BITS)) and 1

/** RFC 6890 and its updates: the IPv4 blocks that are not globally reachable, plus multicast. */
private val V4_REFUSED =
    listOf(
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ).map(::AddressBlock)

private val V6_GLOBAL_UNICAST = AddressBlock("2000::/3")

/** Inside global unicast, what no remote document lives at. */
private val V6_REFUSED =
    listOf(
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
    ).map(::AddressBlock)

private val NAT64 = AddressBlock("64:ff9b::/96")

/** Where, in a NAT64 address, the IPv4 address it carries begins. */
private const val NAT64_V4_OFFSET = 12
