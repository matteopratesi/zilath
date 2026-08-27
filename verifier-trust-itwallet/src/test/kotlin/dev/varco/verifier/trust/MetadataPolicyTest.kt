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
package dev.varco.verifier.trust

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
                    metadata("algs" to listOf("ES256")),
                    listOf(
                        policy("algs" to mapOf("subset_of" to listOf("ES256"))),
                        policy("algs" to mapOf("subset_of" to listOf("ES384"))),
                    ),
                )
            }.withMessageContaining("intersection")
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
