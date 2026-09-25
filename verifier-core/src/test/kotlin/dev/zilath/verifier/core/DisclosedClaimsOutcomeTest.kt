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

import eu.europa.ec.eudi.sdjwt.DisclosableObjectSpecBuilder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * Without a request, the outcome is what the holder disclosed, plus `iss` and `vct`: an
 * allowlist computed per path, where a blocklist of the issuer envelope let every other
 * issuer plaintext claim through (fourth internal review).
 */
class DisclosedClaimsOutcomeTest {
    private fun outcomeOf(
        disclose: (JsonArray) -> Boolean = { true },
        claims: DisclosableObjectSpecBuilder.() -> Unit,
    ): JsonObject {
        val result = verifyPresentation(TestVectors.vectorWith(disclose, claims = claims))
        return (result as VerificationResult.Verified).claims.claims
    }

    private fun json(text: String) = Json.parseToJsonElement(text)

    /** Keeps the disclosures whose claim name (for an array element: value) is not in [names]. */
    private fun withholding(vararg names: String): (JsonArray) -> Boolean =
        { disclosure -> (disclosure.drop(1).firstOrNull() as? JsonPrimitive)?.content !in names }

    @Test
    fun `issuer plaintext is left out and every disclosed claim kept`() {
        val claims =
            outcomeOf {
                claim("serial_no", "CED-000123")
                claim("issuing_country", "IT")
                sdClaim("given_name", "Ada")
                sdClaim("constant_attendance_allowance", true)
            }
        assertThat(claims.keys).containsExactlyInAnyOrder("given_name", "constant_attendance_allowance", "iss", "vct")
    }

    @Test
    fun `a disclosed member of a plaintext object is kept, its plaintext siblings are not`() {
        val claims =
            outcomeOf {
                objClaim("address") {
                    claim("country", "IT")
                    sdClaim("locality", "Roma")
                }
            }
        assertThat(claims["address"]).isEqualTo(json("""{"locality":"Roma"}"""))
    }

    @Test
    fun `a disclosed object is kept whole, with its plaintext members and whatever of it was disclosed`() {
        val spec: DisclosableObjectSpecBuilder.() -> Unit = {
            sdObjClaim("place_of_birth") {
                claim("country", "IT")
                sdClaim("locality", "Roma")
            }
        }
        assertThat(outcomeOf(claims = spec)["place_of_birth"]).isEqualTo(json("""{"country":"IT","locality":"Roma"}"""))
        assertThat(outcomeOf(withholding("locality"), spec)["place_of_birth"]).isEqualTo(json("""{"country":"IT"}"""))
    }

    @Test
    fun `a disclosed element of a plaintext array is kept, plaintext elements are not`() {
        val spec: DisclosableObjectSpecBuilder.() -> Unit = {
            arrClaim("nationalities") {
                claim("XX")
                sdClaim("IT")
                sdClaim("FR")
            }
        }
        assertThat(outcomeOf(claims = spec)["nationalities"]).isEqualTo(json("""["IT","FR"]"""))
        assertThat(outcomeOf(withholding("IT"), spec)["nationalities"]).isEqualTo(json("""["FR"]"""))
        assertThat(outcomeOf(withholding("IT", "FR"), spec)).doesNotContainKey("nationalities")
    }

    @Test
    fun `a disclosed array is kept whole`() {
        val claims =
            outcomeOf {
                sdArrClaim("languages") {
                    claim("it")
                    sdClaim("en")
                }
            }
        assertThat(claims["languages"]).isEqualTo(json("""["it","en"]"""))
    }

    @Test
    fun `plaintext objects in a plaintext array keep only their disclosed members`() {
        val claims =
            outcomeOf {
                arrClaim("addresses") {
                    objClaim {
                        claim("country", "IT")
                        sdClaim("street", "Via Roma 1")
                    }
                    objClaim { claim("country", "FR") }
                }
            }
        assertThat(claims["addresses"]).isEqualTo(json("""[{"street":"Via Roma 1"}]"""))
    }

    @Test
    fun `zero disclosures leave iss and vct, partial ones only what was disclosed`() {
        val spec: DisclosableObjectSpecBuilder.() -> Unit = {
            claim("serial_no", "CED-000123")
            sdClaim("given_name", "Ada")
            sdClaim("family_name", "Lovelace")
        }
        assertThat(outcomeOf({ false }, spec).keys).containsExactlyInAnyOrder("iss", "vct")
        assertThat(
            outcomeOf(withholding("family_name"), spec).keys,
        ).containsExactlyInAnyOrder("given_name", "iss", "vct")
    }

    @Test
    fun `a disclosed envelope claim is still removed`() {
        // The second, defensive filter: jti or iat behind a disclosure would be allowlisted
        // as disclosed, and each is as good as a serial number for linking.
        val claims =
            outcomeOf {
                sdClaim("jti", "urn:uuid:1234")
                sdClaim("sub", "holder-1")
                sdClaim("given_name", "Ada")
            }
        assertThat(claims.keys).containsExactlyInAnyOrder("given_name", "iss", "vct")
    }
}
