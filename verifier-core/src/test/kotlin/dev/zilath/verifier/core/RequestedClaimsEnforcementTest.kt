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
 * [VerificationContext.requestedClaims]: a presentation must answer the DCQL query it was
 * asked, and the outcome carries only what the query asked for. Before the fourth internal
 * review a presentation disclosing nothing at all came back Verified, and one disclosing
 * more than asked handed all of it to the application.
 */
class RequestedClaimsEnforcementTest {
    private val notSatisfied =
        VerificationResult.Rejected(
            RejectionReason.QUERY_NOT_SATISFIED,
            "presentation does not disclose what was requested",
        )

    /** A requested claim from a path written as in DCQL: strings, integers and null. */
    private fun requested(
        vararg path: Any?,
        id: String? = null,
        values: List<JsonPrimitive>? = null,
    ) = RequestedClaim(
        path.map {
            when (it) {
                is String -> ClaimPathSegment.Key(it)
                is Int -> ClaimPathSegment.Index(it)
                null -> ClaimPathSegment.AllElements
                else -> error("not a path component: $it")
            }
        },
        id,
        values,
    )

    private fun query(
        vararg claims: RequestedClaim,
        claimSets: List<List<String>>? = null,
    ) = RequestedClaims(claims.toList(), claimSets)

    private fun verifyWith(
        query: RequestedClaims,
        compact: String = TestVectors.vector(),
    ) = verifyPresentation(compact, testContext(requestedClaims = query))

    private fun claimsOf(result: VerificationResult): JsonObject = (result as VerificationResult.Verified).claims.claims

    private fun json(text: String) = Json.parseToJsonElement(text)

    /** Keeps the disclosures whose claim name (for an array element: value) is not in [names]. */
    private fun withholding(vararg names: String): (JsonArray) -> Boolean =
        { disclosure -> (disclosure.drop(1).firstOrNull() as? JsonPrimitive)?.content !in names }

    private fun credential(
        disclose: (JsonArray) -> Boolean = { true },
        claims: DisclosableObjectSpecBuilder.() -> Unit,
    ) = TestVectors.vectorWith(disclose, claims = claims)

    private val nameQuery = query(requested("given_name"), requested("family_name"))

    @Test
    fun `a presentation disclosing nothing does not satisfy a query`() {
        val nothing =
            credential({ false }) {
                sdClaim("given_name", "Ada")
                sdClaim("family_name", "Lovelace")
            }
        assertThat(verifyWith(nameQuery, nothing)).isEqualTo(notSatisfied)
    }

    @Test
    fun `a presentation disclosing part of what was asked does not satisfy it`() {
        val partial =
            credential(withholding("family_name")) {
                sdClaim("given_name", "Ada")
                sdClaim("family_name", "Lovelace")
            }
        assertThat(verifyWith(nameQuery, partial)).isEqualTo(notSatisfied)
    }

    @Test
    fun `the outcome carries what was asked for, not everything disclosed`() {
        // The vector discloses entitled too: the query did not ask for it.
        val claims = claimsOf(verifyWith(nameQuery))
        assertThat(claims.keys).containsExactlyInAnyOrder("given_name", "family_name", "iss", "vct")
    }

    @Test
    fun `issuer plaintext satisfies a request as a disclosure does`() {
        val compact =
            credential {
                claim("issuing_country", "IT")
                sdClaim("given_name", "Ada")
            }
        val claims = claimsOf(verifyWith(query(requested("issuing_country")), compact))
        assertThat(claims.keys).containsExactlyInAnyOrder("issuing_country", "iss", "vct")
    }

    @Test
    fun `a values constraint must match in type and value`() {
        val asked = { value: JsonPrimitive -> query(requested("entitled", values = listOf(value))) }
        assertThat(claimsOf(verifyWith(asked(JsonPrimitive(true))))["entitled"]).isEqualTo(JsonPrimitive(true))
        assertThat(verifyWith(asked(JsonPrimitive(false)))).isEqualTo(notSatisfied)
        assertThat(verifyWith(asked(JsonPrimitive("true")))).isEqualTo(notSatisfied)
        val either = query(requested("entitled", values = listOf(JsonPrimitive(false), JsonPrimitive(true))))
        assertThat(claimsOf(verifyWith(either))["entitled"]).isEqualTo(JsonPrimitive(true))
    }

    @Test
    fun `claim sets are alternatives, and one complete combination is enough`() {
        val sets =
            query(
                requested("given_name", id = "g"),
                requested("constant_attendance_allowance", id = "c"),
                requested("family_name", id = "f"),
                claimSets = listOf(listOf("g", "c"), listOf("f")),
            )
        val spec: DisclosableObjectSpecBuilder.() -> Unit = {
            sdClaim("given_name", "Ada")
            sdClaim("family_name", "Lovelace")
            sdClaim("constant_attendance_allowance", true)
        }
        // The second option alone.
        val familyOnly = credential(withholding("given_name", "constant_attendance_allowance"), spec)
        assertThat(claimsOf(verifyWith(sets, familyOnly)).keys).containsExactlyInAnyOrder("family_name", "iss", "vct")
        // Half of the first option and nothing of the second.
        val givenOnly = credential(withholding("family_name", "constant_attendance_allowance"), spec)
        assertThat(verifyWith(sets, givenOnly)).isEqualTo(notSatisfied)
        // Everything: every requested claim that is present comes back.
        assertThat(claimsOf(verifyWith(sets, credential(claims = spec))).keys)
            .containsExactlyInAnyOrder("given_name", "family_name", "constant_attendance_allowance", "iss", "vct")
        assertThat(verifyWith(sets, credential({ false }, spec))).isEqualTo(notSatisfied)
    }

    @Test
    fun `a claim present with another value than asked is left out of the outcome`() {
        // Its combination is not needed, so the query is satisfied; but presence in the
        // outcome must mean the value is one of those asked for.
        val sets =
            query(
                requested("constant_attendance_allowance", id = "c", values = listOf(JsonPrimitive(true))),
                requested("family_name", id = "f"),
                claimSets = listOf(listOf("c"), listOf("f")),
            )
        val compact =
            credential {
                sdClaim("family_name", "Lovelace")
                sdClaim("constant_attendance_allowance", false)
            }
        assertThat(claimsOf(verifyWith(sets, compact)).keys).containsExactlyInAnyOrder("family_name", "iss", "vct")
    }

    @Test
    fun `a nested path selects the member and keeps its container only`() {
        val compact =
            credential {
                objClaim("address") {
                    claim("country", "IT")
                    sdClaim("locality", "Roma")
                    sdClaim("street", "Via Roma 1")
                }
            }
        val claims = claimsOf(verifyWith(query(requested("address", "locality")), compact))
        assertThat(claims["address"]).isEqualTo(json("""{"locality":"Roma"}"""))
        val withheld = credential(withholding("locality")) { objClaim("address") { sdClaim("locality", "Roma") } }
        assertThat(verifyWith(query(requested("address", "locality")), withheld)).isEqualTo(notSatisfied)
    }

    @Test
    fun `array components select by index, null selects every element`() {
        val compact =
            credential {
                arrClaim("nationalities") {
                    sdClaim("IT")
                    sdClaim("FR")
                }
            }
        assertThat(claimsOf(verifyWith(query(requested("nationalities", null)), compact))["nationalities"])
            .isEqualTo(json("""["IT","FR"]"""))
        assertThat(claimsOf(verifyWith(query(requested("nationalities", 1)), compact))["nationalities"])
            .isEqualTo(json("""["FR"]"""))
        assertThat(verifyWith(query(requested("nationalities", 2)), compact)).isEqualTo(notSatisfied)
    }

    @Test
    fun `values over null keep only the matching elements, and never match an array itself`() {
        val compact =
            credential {
                arrClaim("nationalities") {
                    sdClaim("IT")
                    sdClaim("FR")
                }
            }
        val it = listOf(JsonPrimitive("IT"))
        assertThat(claimsOf(verifyWith(query(requested("nationalities", null, values = it)), compact))["nationalities"])
            .isEqualTo(json("""["IT"]"""))
        // The path selects the array, and an array is not a string: §6.3 compares the value
        // the pointer selects, so a query must reach into the array with null.
        assertThat(verifyWith(query(requested("nationalities", values = it)), compact)).isEqualTo(notSatisfied)
    }

    @Test
    fun `a pointer into the wrong kind of element is an error, not a match`() {
        // OpenID4VP §7: a string component on something that is not an object, an index or
        // null on something that is not an array, abort processing.
        assertThat(verifyWith(query(requested("given_name", "first")))).isEqualTo(notSatisfied)
        assertThat(verifyWith(query(requested("given_name", 0)))).isEqualTo(notSatisfied)
        assertThat(verifyWith(query(requested("given_name", null)))).isEqualTo(notSatisfied)
    }

    @Test
    fun `one selected element of the wrong kind aborts the whole pointer`() {
        // Not "skip the element that does not fit": §7 aborts with an error when ANY
        // selected element is not an object for a string component.
        val compact =
            credential {
                arrClaim("mixed") {
                    objClaim { sdClaim("type", "a") }
                    claim("plain")
                }
            }
        assertThat(verifyWith(query(requested("mixed", null, "type")), compact)).isEqualTo(notSatisfied)
    }

    @Test
    fun `an element missing from one selected array only drops that element`() {
        val compact =
            credential {
                arrClaim("degrees") {
                    objClaim { sdClaim("type", "Bachelor") }
                    objClaim { claim("year", 2020) }
                }
            }
        val claims = claimsOf(verifyWith(query(requested("degrees", null, "type")), compact))
        assertThat(claims["degrees"]).isEqualTo(json("""[{"type":"Bachelor"}]"""))
    }

    @Test
    fun `a requested envelope claim is checked but never handed over`() {
        // exp is plaintext and present, so the query is satisfied; the envelope stays out of
        // every outcome, requested or not (it identifies the credential).
        val claims = claimsOf(verifyWith(query(requested("exp"), requested("given_name"))))
        assertThat(claims.keys).containsExactlyInAnyOrder("given_name", "iss", "vct")
    }
}
