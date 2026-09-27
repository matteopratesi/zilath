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

import dev.zilath.verifier.core.HttpDocumentFetcher.Destinations.LOOPBACK
import dev.zilath.verifier.core.HttpDocumentFetcher.Destinations.PUBLIC_AND_LOOPBACK
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.net.InetAddress

class NetworkDestinationsTest {
    private fun reachable(
        literal: String,
        destinations: HttpDocumentFetcher.Destinations = HttpDocumentFetcher.Destinations.PUBLIC,
    ) = isReachableDestination(InetAddress.getByName(literal), destinations)

    @Test
    fun `globally routable addresses are reached`() {
        listOf(
            "8.8.8.8",
            "1.1.1.1",
            "9.255.255.255",
            "11.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.0",
            "192.167.255.255",
            "192.169.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
            "2606:4700:4700::1111",
            "2a00:1450:4001::200e",
            "2001:200::1",
            // NAT64 in front of a public IPv4 address.
            "64:ff9b::808:808",
        ).forEach { assertThat(reachable(it)).`as`(it).isTrue() }
    }

    @Test
    fun `addresses no remote document lives at are refused`() {
        listOf(
            "0.0.0.0",
            "0.255.255.255",
            "10.0.0.1",
            "10.255.255.255",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            // IPv4-mapped: the JVM reads it as the IPv4 address it maps.
            "::ffff:10.0.0.1",
            "::",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "2001::1",
            "2001:1ff:ffff::1",
            "2001:db8::1",
            "2002:a00:1::1",
            "3fff::1",
            "64:ff9b:1::1",
            "100::1",
            // NAT64 in front of a private or a metadata address.
            "64:ff9b::a00:1",
            "64:ff9b::a9fe:a9fe",
        ).forEach { assertThat(reachable(it)).`as`(it).isFalse() }
    }

    @Test
    fun `loopback is reached only when admitted, and admitting it opens nothing else`() {
        listOf("127.0.0.1", "127.1.2.3", "::1").forEach {
            assertThat(reachable(it)).`as`(it).isFalse()
            assertThat(reachable(it, PUBLIC_AND_LOOPBACK)).`as`(it).isTrue()
            assertThat(reachable(it, LOOPBACK)).`as`(it).isTrue()
        }
        listOf("10.0.0.1", "169.254.169.254", "fe80::1", "64:ff9b::7f00:1").forEach {
            assertThat(reachable(it, PUBLIC_AND_LOOPBACK)).`as`(it).isFalse()
            assertThat(reachable(it, LOOPBACK)).`as`(it).isFalse()
        }
    }

    @Test
    fun `loopback alone reaches nothing public`() {
        listOf("8.8.8.8", "2606:4700:4700::1111", "64:ff9b::808:808").forEach {
            assertThat(reachable(it, PUBLIC_AND_LOOPBACK)).`as`(it).isTrue()
            assertThat(reachable(it, LOOPBACK)).`as`(it).isFalse()
        }
    }
}
