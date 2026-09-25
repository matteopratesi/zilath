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
    fun `an unsupported operator fails closed`() {
        assertThatExceptionOfType(TrustFailure::class.java)
            .isThrownBy {
                MetadataPolicy.resolve(
                    metadata("a" to "x"),
                    listOf(policy("a" to mapOf("regexp" to ".*"))),
                )
            }.withMessageContaining("unsupported")
    }
}
