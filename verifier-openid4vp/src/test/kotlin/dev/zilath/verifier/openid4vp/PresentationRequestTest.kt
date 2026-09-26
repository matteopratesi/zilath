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
package dev.zilath.verifier.openid4vp

import dev.zilath.verifier.core.ClaimPathSegment
import dev.zilath.verifier.core.RequestedClaim
import dev.zilath.verifier.core.RequestedClaims
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.junit.jupiter.api.Test

class PresentationRequestTest {
    private fun query(json: String): JsonObject = Json.parseToJsonElement(json).jsonObject

    /** A single `ced` credential query with [members] spliced in. */
    private fun ced(members: String = """"claims": [{"path": ["constant_attendance_allowance"]}]"""): JsonObject =
        query(
            """{"credentials": [{"id": "ced", "format": "dc+sd-jwt",
               "meta": {"vct_values": ["urn:ced"]}${if (members.isBlank()) "" else ", $members"}}]}""",
        )

    @Test
    fun `claims become requested claims, path segment by path segment`() {
        val request =
            PresentationRequest(
                ced(
                    """"claims": [
                        {"id": "a", "path": ["address", "locality"]},
                        {"id": "b", "path": ["nationalities", 0]},
                        {"id": "c", "path": ["degrees", null, "type"], "values": ["MSc", 3, true]}
                    ],
                    "claim_sets": [["a", "c"], ["b"]]""",
                ),
                "ced",
            )
        assertThat(request.requestedClaims()).isEqualTo(
            RequestedClaims(
                claims =
                    listOf(
                        RequestedClaim(
                            listOf(ClaimPathSegment.Key("address"), ClaimPathSegment.Key("locality")),
                            id = "a",
                        ),
                        RequestedClaim(
                            listOf(ClaimPathSegment.Key("nationalities"), ClaimPathSegment.Index(0)),
                            id = "b",
                        ),
                        RequestedClaim(
                            listOf(
                                ClaimPathSegment.Key("degrees"),
                                ClaimPathSegment.AllElements,
                                ClaimPathSegment.Key("type"),
                            ),
                            id = "c",
                            values = listOf(JsonPrimitive("MSc"), JsonPrimitive(3), JsonPrimitive(true)),
                        ),
                    ),
                claimSets = listOf(listOf("a", "c"), listOf("b")),
            ),
        )
    }

    @Test
    fun `a string that looks like a number is still a member name`() {
        // §7: the TYPE of the component decides — "0" names a member, 0 indexes an array.
        val request = PresentationRequest(ced(""""claims": [{"path": ["codes", "0"]}]"""), "ced")
        assertThat(
            request
                .requestedClaims()!!
                .claims
                .single()
                .path,
        ).containsExactly(ClaimPathSegment.Key("codes"), ClaimPathSegment.Key("0"))
    }

    @Test
    fun `the helper queries carry their claim paths`() {
        assertThat(PresentationRequest.forTestPid("urn:pid").requestedClaims()).isEqualTo(
            RequestedClaims(
                listOf(
                    RequestedClaim(listOf(ClaimPathSegment.Key("given_name"))),
                    RequestedClaim(listOf(ClaimPathSegment.Key("family_name"))),
                ),
            ),
        )
    }

    @Test
    fun `a query without claims asks for none`() {
        assertThat(PresentationRequest(ced(members = ""), "ced").requestedClaims()).isNull()
        // forVct with no paths leaves claims out rather than sending the empty array DCQL forbids.
        val bare = PresentationRequest.forVct("urn:ced", emptyList(), "ced")
        assertThat(bare.dcqlQuery.toString()).doesNotContain("claims")
        assertThat(bare.requestedClaims()).isNull()
    }

    @Test
    fun `a query that names no credential type is refused, as the type check would be off`() {
        // expectedVcts() empty means the verifier checks no type: any credential a trusted
        // issuer signed would answer. That is what these queries used to produce.
        val untyped =
            listOf(
                // no meta at all
                """{"id": "ced", "format": "dc+sd-jwt", "claims": [{"path": ["x"]}]}""",
                // meta not an object
                """{"id": "ced", "format": "dc+sd-jwt", "meta": ["urn:ced"]}""",
                """{"id": "ced", "format": "dc+sd-jwt", "meta": "urn:ced"}""",
                // meta without vct_values, or with the member misspelled
                """{"id": "ced", "format": "dc+sd-jwt", "meta": {}}""",
                """{"id": "ced", "format": "dc+sd-jwt", "meta": {"vct_value": ["urn:ced"]}}""",
                // vct_values empty, not an array, or holding a blank or non-string type
                """{"id": "ced", "format": "dc+sd-jwt", "meta": {"vct_values": []}}""",
                """{"id": "ced", "format": "dc+sd-jwt", "meta": {"vct_values": "urn:ced"}}""",
                """{"id": "ced", "format": "dc+sd-jwt", "meta": {"vct_values": [" "]}}""",
                """{"id": "ced", "format": "dc+sd-jwt", "meta": {"vct_values": [1]}}""",
            )
        untyped.forEach { credential ->
            assertThatIllegalArgumentException()
                .describedAs(credential)
                .isThrownBy { PresentationRequest(query("""{"credentials": [$credential]}"""), "ced") }
        }
        assertThat(PresentationRequest(ced(), "ced").expectedVcts()).containsExactly("urn:ced")
    }

    @Test
    fun `only SD-JWT VC formats are requested`() {
        // What comes back is verified as an SD-JWT VC: a query for anything else would be
        // answered with a credential the verifier cannot read.
        val format = { value: String ->
            query("""{"credentials": [{"id": "ced", $value "meta": {"vct_values": ["urn:ced"]}}]}""")
        }
        listOf("", """"format": "mso_mdoc",""", """"format": "jwt_vc_json",""", """"format": 1,""").forEach {
            assertThatIllegalArgumentException().describedAs(it).isThrownBy { PresentationRequest(format(it), "ced") }
        }
        // The pre-1.0 identifier names the same credentials, which the verifier accepts.
        assertThat(PresentationRequest(format(""""format": "vc+sd-jwt","""), "ced").expectedVcts())
            .containsExactly("urn:ced")
        assertThat(PresentationRequest(format(""""format": "dc+sd-jwt","""), "ced").expectedVcts())
            .containsExactly("urn:ced")
    }

    @Test
    fun `members the response side does not evaluate are refused`() {
        // trusted_authorities would let the wallet choose by issuer on a rule nobody checks;
        // a presentation without key binding is always rejected, so asking for one is a
        // request no holder can satisfy.
        assertThatIllegalArgumentException().isThrownBy {
            PresentationRequest(ced(""""trusted_authorities": [{"type": "aki", "values": ["s9tIpP"]}]"""), "ced")
        }
        listOf("false", "\"true\"", "1").forEach { value ->
            assertThatIllegalArgumentException().describedAs(value).isThrownBy {
                PresentationRequest(ced(""""require_cryptographic_holder_binding": $value"""), "ced")
            }
        }
        assertThat(
            PresentationRequest(ced(""""require_cryptographic_holder_binding": true"""), "ced").credentialQueryId,
        ).isEqualTo("ced")
    }

    @Test
    fun `the helper queries are ones the library evaluates`() {
        val ced = PresentationRequest.forVct("urn:ced", listOf("constant_attendance_allowance"), "ced")
        assertThat(ced.expectedVcts()).containsExactly("urn:ced")
        assertThat(PresentationRequest.forTestPid("urn:pid").expectedVcts()).containsExactly("urn:pid")
        assertThatIllegalArgumentException().isThrownBy { PresentationRequest.forVct(" ", emptyList(), "ced") }
    }

    @Test
    fun `a query the library cannot evaluate is refused when the request is built`() {
        val refused =
            listOf(
                "{}",
                """{"credentials": {}}""",
                """{"credentials": []}""",
                """{"credentials": ["ced"]}""",
                """{"credentials": [{"id": "pid", "format": "dc+sd-jwt"}]}""",
            )
        refused.forEach { json ->
            assertThatIllegalArgumentException().isThrownBy { PresentationRequest(query(json), "ced") }
        }
    }

    @Test
    fun `a query asking for more than one presentation is refused`() {
        // Only the credential query named credentialQueryId is ever verified: a second
        // query, credential_sets or multiple would ask the wallet for something the
        // response side then ignores, present, absent or garbage.
        assertThatIllegalArgumentException().isThrownBy {
            PresentationRequest(
                query(
                    """{"credentials": [
                        {"id": "pid", "format": "dc+sd-jwt"},
                        {"id": "ced", "format": "dc+sd-jwt"}
                    ]}""",
                ),
                "pid",
            )
        }
        assertThatIllegalArgumentException().isThrownBy {
            PresentationRequest(
                query(
                    """{"credentials": [{"id": "ced", "format": "dc+sd-jwt"}],
                        "credential_sets": [{"options": [["ced"]]}]}""",
                ),
                "ced",
            )
        }
        assertThatIllegalArgumentException().isThrownBy {
            PresentationRequest(ced(""""multiple": true"""), "ced")
        }
        assertThatIllegalArgumentException().isThrownBy {
            PresentationRequest(ced(""""multiple": "false""""), "ced")
        }
        assertThat(PresentationRequest(ced(""""multiple": false"""), "ced").credentialQueryId).isEqualTo("ced")
    }

    @Test
    fun `claims that do not follow the DCQL grammar are refused`() {
        val refused =
            listOf(
                // empty claims, claims not an array, entry not an object, no path
                """"claims": []""",
                """"claims": {"path": ["x"]}""",
                """"claims": ["x"]""",
                """"claims": [{"id": "a"}]""",
                // path components: empty, starting with an index, negative, fractional,
                // beyond an int, boolean, object
                """"claims": [{"path": []}]""",
                """"claims": [{"path": [0]}]""",
                """"claims": [{"path": ["x", -1]}]""",
                """"claims": [{"path": ["x", 1.5]}]""",
                """"claims": [{"path": ["x", 4294967296]}]""",
                """"claims": [{"path": ["x", true]}]""",
                """"claims": [{"path": ["x", {"a": 1}]}]""",
                // values: not an array, empty, holding null, a float or an object
                """"claims": [{"path": ["x"], "values": "a"}]""",
                """"claims": [{"path": ["x"], "values": []}]""",
                """"claims": [{"path": ["x"], "values": [null]}]""",
                """"claims": [{"path": ["x"], "values": [1.5]}]""",
                """"claims": [{"path": ["x"], "values": [{"a": 1}]}]""",
                // ids: not a string, outside the allowed characters, duplicated
                """"claims": [{"id": 1, "path": ["x"]}]""",
                """"claims": [{"id": "a b", "path": ["x"]}]""",
                """"claims": [{"id": "a", "path": ["x"]}, {"id": "a", "path": ["y"]}]""",
                // claim_sets: without claims, naming an unknown id, not arrays
                """"claim_sets": [["a"]]""",
                """"claims": [{"id": "a", "path": ["x"]}], "claim_sets": [["b"]]""",
                """"claims": [{"id": "a", "path": ["x"]}], "claim_sets": ["a"]""",
                """"claims": [{"id": "a", "path": ["x"]}], "claim_sets": [[1]]""",
                // vct_values: empty or not strings
                """"meta": {"vct_values": []}""",
            )
        refused.forEach { members ->
            val json =
                if (members.startsWith("\"meta\"")) {
                    query("""{"credentials": [{"id": "ced", "format": "dc+sd-jwt", $members}]}""")
                } else {
                    ced(members)
                }
            assertThatIllegalArgumentException()
                .describedAs(members)
                .isThrownBy { PresentationRequest(json, "ced") }
        }
        assertThatIllegalArgumentException().isThrownBy {
            PresentationRequest(
                query("""{"credentials": [{"id": "ced", "format": "dc+sd-jwt", "meta": {"vct_values": [1]}}]}"""),
                "ced",
            )
        }
    }
}
