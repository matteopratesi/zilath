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

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.junit.jupiter.api.Test

class MetadataPolicyTest {
    private fun policy(vararg parameters: Pair<String, Map<String, Any?>>): Map<String, Any?> =
        mapOf("openid_credential_issuer" to mapOf(*parameters))

    private fun metadata(vararg entries: Pair<String, Any?>): Map<String, Any?> =
        mapOf("openid_credential_issuer" to mapOf(*entries))

    private fun issuerSection(resolved: Map<String, Any?>): Map<*, *> =
        resolved["openid_credential_issuer"] as Map<*, *>

    @Test
    fun `value replaces, add unions, default fills only absences`() {
        val resolved =
            MetadataPolicy.resolve(
                metadata("a" to "leaf", "list" to listOf("x")),
                listOf(
                    policy(
                        "a" to mapOf("value" to "forced"),
                        "list" to mapOf("add" to listOf("y")),
                        "absent" to mapOf("default" to "filled"),
                        "present" to mapOf("default" to "ignored"),
                    ),
                ),
            )
        val section = issuerSection(resolved)
        assertThat(section["a"]).isEqualTo("forced")
        assertThat(section["list"]).isEqualTo(listOf("x", "y"))
        assertThat(section["absent"]).isEqualTo("filled")
    }

    @Test
    fun `subset_of restricts and one_of and superset_of validate`() {
        val resolved =
            MetadataPolicy.resolve(
                metadata("algs" to listOf("ES256", "RS256"), "mode" to "direct_post.jwt"),
                listOf(
                    policy(
                        "algs" to mapOf("subset_of" to listOf("ES256", "ES384")),
                        "mode" to mapOf("one_of" to listOf("direct_post.jwt", "direct_post")),
                    ),
                ),
            )
        assertThat(issuerSection(resolved)["algs"]).isEqualTo(listOf("ES256"))

        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    metadata("mode" to "fragment"),
                    listOf(policy("mode" to mapOf("one_of" to listOf("direct_post.jwt")))),
                )
            }.withMessageContaining("one_of")
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    metadata("algs" to listOf("ES256")),
                    listOf(policy("algs" to mapOf("superset_of" to listOf("ES256", "ES384")))),
                )
            }.withMessageContaining("superset_of")
    }

    @Test
    fun `essential fails on absence and passes on presence`() {
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(metadata(), listOf(policy("jwks" to mapOf("essential" to true))))
            }.withMessageContaining("essential")
        val resolved =
            MetadataPolicy.resolve(
                metadata("jwks" to mapOf("keys" to emptyList<Any>())),
                listOf(policy("jwks" to mapOf("essential" to true))),
            )
        assertThat(issuerSection(resolved)["jwks"]).isNotNull()
    }

    @Test
    fun `superior policies merge anchor-first and conflicts fail`() {
        // Anchor narrows to {ES256, ES384}; the intermediate narrows further to {ES256}.
        val resolved =
            MetadataPolicy.resolve(
                metadata("algs" to listOf("ES256", "ES384", "RS256")),
                listOf(
                    policy("algs" to mapOf("subset_of" to listOf("ES256", "ES384"))),
                    policy("algs" to mapOf("subset_of" to listOf("ES256", "RS256"))),
                ),
            )
        assertThat(issuerSection(resolved)["algs"]).isEqualTo(listOf("ES256"))

        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    metadata("a" to "x"),
                    listOf(
                        policy("a" to mapOf("value" to "anchor-forced")),
                        policy("a" to mapOf("value" to "intermediate-forced")),
                    ),
                )
            }.withMessageContaining("conflicting")
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    metadata("mode" to "x"),
                    listOf(
                        policy("mode" to mapOf("one_of" to listOf("x"))),
                        policy("mode" to mapOf("one_of" to listOf("y"))),
                    ),
                )
            }.withMessageContaining("intersection")
        // Two subset_of merging to an empty intersection is LEGAL: it resolves to [].
        val emptied =
            MetadataPolicy.resolve(
                metadata("algs" to listOf("ES256")),
                listOf(
                    policy("algs" to mapOf("subset_of" to listOf("ES256"))),
                    policy("algs" to mapOf("subset_of" to listOf("ES384"))),
                ),
            )
        assertThat(issuerSection(emptied)["algs"]).isEqualTo(emptyList<Any?>())
    }

    @Test
    fun `operator values are type-checked and default null is refused`() {
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(metadata(), listOf(policy("a" to mapOf("add" to "ES256"))))
            }.withMessageContaining("must be an array")
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(metadata(), listOf(policy("a" to mapOf("default" to null))))
            }.withMessageContaining("must not be null")
    }

    @Test
    fun `value combines with other operators only under the spec relationships`() {
        // Legal: the forced value satisfies every companion operator.
        val resolved =
            MetadataPolicy.resolve(
                metadata("algs" to listOf("RS256")),
                listOf(
                    policy(
                        "algs" to
                            mapOf(
                                "value" to listOf("ES256", "ES384"),
                                "add" to listOf("ES384"),
                                "subset_of" to listOf("ES256", "ES384", "ES512"),
                                "superset_of" to listOf("ES256"),
                            ),
                    ),
                ),
            )
        assertThat(issuerSection(resolved)["algs"]).isEqualTo(listOf("ES256", "ES384"))
        // Illegal: add outside value.
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    metadata(),
                    listOf(policy("a" to mapOf("value" to listOf("ES256"), "add" to listOf("RS256")))),
                )
            }.withMessageContaining("subset of value")
        // Illegal combinations arising from the MERGE of two policies fail too.
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    metadata(),
                    listOf(
                        policy("a" to mapOf("one_of" to listOf("x"))),
                        policy("a" to mapOf("add" to listOf("y"))),
                    ),
                )
            }.withMessageContaining("cannot combine")
    }

    @Test
    fun `incompatible subset_of and superset_of operands fail at validation`() {
        // The CodeRabbit counterexample: without the operand check, ["ES256","RS256"]
        // with subset_of ["ES256"] and superset_of ["RS256"] would resolve to ["ES256"].
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    metadata("algs" to listOf("ES256", "RS256")),
                    listOf(
                        policy(
                            "algs" to
                                mapOf(
                                    "subset_of" to listOf("ES256"),
                                    "superset_of" to listOf("RS256"),
                                ),
                        ),
                    ),
                )
            }.withMessageContaining("superset of superset_of")
    }

    @Test
    fun `a value null directive removes the parameter and survives merging`() {
        val resolved =
            MetadataPolicy.resolve(
                metadata("a" to "leaf"),
                listOf(policy("a" to mapOf("value" to null))),
            )
        assertThat(issuerSection(resolved).containsKey("a")).isFalse()
        // A subordinate cannot silently override the anchor's value: null.
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    metadata("a" to "leaf"),
                    listOf(
                        policy("a" to mapOf("value" to null)),
                        policy("a" to mapOf("value" to "sneaky")),
                    ),
                )
            }.withMessageContaining("conflicting")
    }

    @Test
    fun `an empty subset_of result stays present and satisfies essential`() {
        val resolved =
            MetadataPolicy.resolve(
                metadata("algs" to listOf("RS256")),
                listOf(
                    policy("algs" to mapOf("subset_of" to listOf("ES256"), "essential" to true)),
                ),
            )
        assertThat(issuerSection(resolved)["algs"]).isEqualTo(emptyList<Any?>())
    }

    @Test
    fun `a policy is applied only to the entity types the leaf publishes`() {
        val resolved =
            MetadataPolicy.resolve(
                metadata("jwks" to mapOf("keys" to emptyList<Any>())),
                listOf(
                    mapOf(
                        "openid_credential_issuer" to mapOf("jwks" to mapOf("essential" to true)),
                        // Essential parameters of a type the leaf is not: no failure...
                        "wallet_provider" to mapOf("aal_values_supported" to mapOf("essential" to true)),
                        // ...and no section fabricated for it either.
                        "openid_relying_party" to mapOf("redirect_uris" to mapOf("default" to listOf("https://x"))),
                    ),
                ),
            )
        assertThat(resolved.keys).containsExactly("openid_credential_issuer")
    }

    @Test
    fun `a malformed policy for a type the leaf does not publish still invalidates the chain`() {
        // Validation covers the whole chain's policy (OID-FED §6.1.4.1); only its
        // application is limited to the types present.
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    metadata("a" to "x"),
                    listOf(mapOf("wallet_provider" to mapOf("grant_types_supported" to mapOf("add" to "not-a-list")))),
                )
            }.withMessageContaining("must be an array")
    }

    @Test
    fun `superior metadata is not grafted onto an entity type the leaf does not publish`() {
        val overlaid =
            MetadataPolicy.overlay(
                mapOf("federation_entity" to mapOf("organization_name" to "leaf")),
                mapOf("openid_credential_issuer" to mapOf("jwks" to mapOf("keys" to emptyList<Any>()))),
            )
        assertThat(overlaid.keys).containsExactly("federation_entity")
    }

    @Test
    fun `the immediate superior statement metadata overrides the leaf`() {
        val overlaid =
            MetadataPolicy.overlay(
                mapOf("openid_credential_issuer" to mapOf("a" to "leaf", "b" to "kept")),
                mapOf("openid_credential_issuer" to mapOf("a" to "superior")),
            )
        val section = overlaid["openid_credential_issuer"] as Map<*, *>
        assertThat(section["a"]).isEqualTo("superior")
        assertThat(section["b"]).isEqualTo("kept")
    }

    @Test
    fun `a null metadata parameter is malformed, not present for essential nor absent for one_of`() {
        // Parsed the way entity statements are, so the explicit null survives as it would.
        val section =
            com.nimbusds.jose.util.JSONObjectUtils
                .parse("""{"mode": null, "n": 1}""")
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    mapOf("openid_credential_issuer" to section),
                    listOf(policy("mode" to mapOf("one_of" to listOf("direct_post.jwt"), "essential" to true))),
                )
            }.withMessageContaining("is null")
        // Even with no policy on it: the document itself is malformed (OID-FED §5).
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy { MetadataPolicy.resolve(mapOf("openid_credential_issuer" to section), emptyList()) }
            .withMessageContaining("is null")
    }

    @Test
    fun `a metadata section that is not an object is malformed`() {
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy { MetadataPolicy.resolve(mapOf("openid_credential_issuer" to "keys"), emptyList()) }
            .withMessageContaining("not a JSON object")
    }

    @Test
    fun `array operators on a parameter that is not an array are a policy error`() {
        val notAnArray = "a metadata_policy array operator applies to a parameter that is not an array"
        for (operator in listOf("add", "subset_of", "superset_of")) {
            assertThatExceptionOfType(TrustFailure::class.java)
                .describedAs(operator)
                .isThrownBy {
                    MetadataPolicy.resolve(
                        metadata("mode" to "direct_post"),
                        listOf(policy("mode" to mapOf(operator to listOf("direct_post")))),
                    )
                }.withMessageContaining(notAnArray)
        }
        // An object is not an array either: subset_of on jwks used to turn the key set
        // into a one-element list.
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    metadata("jwks" to mapOf("keys" to emptyList<Any>())),
                    listOf(policy("jwks" to mapOf("subset_of" to listOf(mapOf("keys" to emptyList<Any>()))))),
                )
            }.withMessageContaining(notAnArray)
        // A value forced alongside an array operator must be an array too.
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    metadata(),
                    listOf(policy("mode" to mapOf("value" to "x", "add" to listOf("x")))),
                )
            }.withMessageContaining("must be an array")
    }

    @Test
    fun `scope is a space-separated list the array operators work on`() {
        // OID-FED §6.1.3.1.8: the OAuth scope string is processed as a string array by the
        // policy operators, and the result is a space-separated string again.
        fun verifier(vararg parameters: Pair<String, Map<String, Any?>>) =
            mapOf("openid_credential_verifier" to mapOf(*parameters))

        fun scopeUnder(operators: Map<String, Any?>): Any? {
            val leaf = mapOf("openid_credential_verifier" to mapOf("scope" to "openid profile"))
            val resolved = MetadataPolicy.resolve(leaf, listOf(verifier("scope" to operators)))
            return (resolved["openid_credential_verifier"] as Map<*, *>)["scope"]
        }
        assertThat(scopeUnder(mapOf("subset_of" to listOf("openid", "profile", "email")))).isEqualTo("openid profile")
        assertThat(scopeUnder(mapOf("superset_of" to listOf("openid")))).isEqualTo("openid profile")
        assertThat(scopeUnder(mapOf("subset_of" to listOf("openid")))).isEqualTo("openid")
        assertThat(scopeUnder(mapOf("add" to listOf("email")))).isEqualTo("openid profile email")
        // A forced value written as a string is a list of scope values too.
        assertThat(scopeUnder(mapOf("value" to "openid email", "subset_of" to listOf("openid", "email", "phone"))))
            .isEqualTo("openid email")
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy { scopeUnder(mapOf("superset_of" to listOf("email"))) }
            .withMessageContaining("violates superset_of")
        // Any other string parameter is still not an array.
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    mapOf("openid_credential_verifier" to mapOf("response_mode" to "direct_post.jwt fragment")),
                    listOf(verifier("response_mode" to mapOf("subset_of" to listOf("direct_post.jwt")))),
                )
            }.withMessageContaining("not an array")
    }

    @Test
    fun `add outside subset_of is a policy error, directly and after merging`() {
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    metadata("algs" to listOf("ES256")),
                    listOf(policy("algs" to mapOf("add" to listOf("RS256"), "subset_of" to listOf("ES256")))),
                )
            }.withMessageContaining("subset of subset_of")
        // The anchor restricts, the intermediate tries to add.
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    metadata("algs" to listOf("ES256")),
                    listOf(
                        policy("algs" to mapOf("subset_of" to listOf("ES256"))),
                        policy("algs" to mapOf("add" to listOf("RS256"))),
                    ),
                )
            }.withMessageContaining("subset of subset_of")
        // Three single policies, each legal on its own: the merged subset_of narrows below add.
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    metadata("algs" to listOf("ES256")),
                    listOf(
                        policy("algs" to mapOf("subset_of" to listOf("ES256", "RS256"))),
                        policy("algs" to mapOf("add" to listOf("RS256"))),
                        policy("algs" to mapOf("subset_of" to listOf("ES256"))),
                    ),
                )
            }.withMessageContaining("subset of subset_of")
    }

    @Test
    fun `a subordinate cannot widen a value its superior forced`() {
        // The anchor forces [ES256]; an intermediate adds RS256. Without the check on the
        // MERGED operators this resolves to [ES256, RS256]: the test asserts the refusal
        // itself, not only its wording, so dropping that check cannot pass on a message.
        val outcome =
            runCatching {
                MetadataPolicy.resolve(
                    metadata("algs" to listOf("ES256")),
                    listOf(
                        policy("algs" to mapOf("value" to listOf("ES256"))),
                        policy("algs" to mapOf("add" to listOf("RS256"))),
                    ),
                )
            }
        assertThat(outcome.getOrNull()).describedAs("resolved to %s", outcome.getOrNull()).isNull()
        assertThat(outcome.exceptionOrNull())
            .isInstanceOf(TrustFailure::class.java)
            .hasMessageContaining("subset of value")
    }

    @Test
    fun `an operator this library does not understand is ignored unless it is critical`() {
        // This test used to assert that an unknown operator fails the chain. OID-FED
        // §6.1.3.2 says the opposite: "MUST ignore additional operators that are not
        // understood", unless they are named in metadata_policy_crit.
        val resolved =
            MetadataPolicy.resolve(
                metadata("a" to "x", "algs" to listOf("ES256", "RS256")),
                listOf(
                    policy(
                        "a" to mapOf("regexp" to ".*"),
                        // Known operators next to an unknown one still apply.
                        "algs" to mapOf("subset_of" to listOf("ES256"), "regexp" to "^ES"),
                    ),
                ),
            )
        assertThat(issuerSection(resolved)["a"]).isEqualTo("x")
        assertThat(issuerSection(resolved)["algs"]).isEqualTo(listOf("ES256"))
    }

    @Test
    fun `the IT-Wallet example shape of vp_formats does not break resolution`() {
        // IT-Wallet 1.4.6 §6.9: a nested {"dc+sd-jwt": {...}} where an operator would be.
        val resolved =
            MetadataPolicy.resolve(
                mapOf(
                    "openid_credential_verifier" to
                        mapOf(
                            "vp_formats" to mapOf("dc+sd-jwt" to emptyMap<String, Any>()),
                        ),
                ),
                listOf(
                    mapOf(
                        "openid_credential_verifier" to
                            mapOf(
                                "vp_formats" to
                                    mapOf("dc+sd-jwt" to mapOf("sd-jwt_alg_values" to listOf("ES256"))),
                            ),
                    ),
                ),
            )
        assertThat(resolved.keys).containsExactly("openid_credential_verifier")
    }

    @Test
    fun `an operator the chain declares critical must be understood`() {
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    metadata("a" to "x"),
                    listOf(policy("a" to mapOf("regexp" to ".*"))),
                    criticalOperators = setOf("regexp"),
                )
            }.withMessageContaining("critical")
        // Declared critical is enough, used or not: the superior said a verifier that
        // cannot apply it must not trust the chain.
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(metadata("a" to "x"), emptyList(), criticalOperators = setOf("regexp"))
            }.withMessageContaining("critical")
        // A critical operator this library does implement is simply applied.
        val resolved =
            MetadataPolicy.resolve(
                metadata("a" to "x"),
                listOf(policy("a" to mapOf("value" to "forced"))),
                criticalOperators = setOf("value"),
            )
        assertThat(issuerSection(resolved)["a"]).isEqualTo("forced")
    }
}
