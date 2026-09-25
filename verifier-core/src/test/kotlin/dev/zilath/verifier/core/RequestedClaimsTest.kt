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

import kotlinx.serialization.json.JsonPrimitive
import org.assertj.core.api.Assertions.assertThatCode
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class RequestedClaimsTest {
    private val name = RequestedClaim(listOf(ClaimPathSegment.Key("given_name")), id = "a")
    private val flag =
        RequestedClaim(listOf(ClaimPathSegment.Key("entitled")), id = "b", values = listOf(JsonPrimitive(true)))

    @Test
    fun `a well-formed query with claim sets is accepted`() {
        assertThatCode {
            RequestedClaims(listOf(name, flag), claimSets = listOf(listOf("a", "b"), listOf("b")))
            RequestedClaim(
                listOf(ClaimPathSegment.Key("address"), ClaimPathSegment.AllElements, ClaimPathSegment.Index(0)),
            )
        }.doesNotThrowAnyException()
    }

    @Test
    fun `malformed queries are refused at construction`() {
        assertThatThrownBy { RequestedClaims(emptyList()) }.isInstanceOf(IllegalArgumentException::class.java)
        assertThatThrownBy { RequestedClaims(listOf(name), claimSets = emptyList()) }
            .isInstanceOf(IllegalArgumentException::class.java)
        assertThatThrownBy { RequestedClaims(listOf(name), claimSets = listOf(emptyList())) }
            .isInstanceOf(IllegalArgumentException::class.java)
        assertThatThrownBy { RequestedClaims(listOf(name), claimSets = listOf(listOf("zz"))) }
            .isInstanceOf(IllegalArgumentException::class.java)
        assertThatThrownBy { RequestedClaims(listOf(name.copy(id = null)), claimSets = listOf(listOf("a"))) }
            .isInstanceOf(IllegalArgumentException::class.java)
        assertThatThrownBy { RequestedClaim(emptyList()) }.isInstanceOf(IllegalArgumentException::class.java)
        assertThatThrownBy { RequestedClaim(listOf(ClaimPathSegment.Index(0))) }
            .isInstanceOf(IllegalArgumentException::class.java)
        assertThatThrownBy { RequestedClaim(listOf(ClaimPathSegment.Key("x")), values = emptyList()) }
            .isInstanceOf(IllegalArgumentException::class.java)
        assertThatThrownBy { ClaimPathSegment.Index(-1) }.isInstanceOf(IllegalArgumentException::class.java)
    }
}
