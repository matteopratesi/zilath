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

import dev.zilath.verifier.core.TestVectors
import dev.zilath.verifier.trust.FederationFixtures.anchorStatementAboutLeaf
import dev.zilath.verifier.trust.FederationFixtures.chainEvaluator
import dev.zilath.verifier.trust.FederationFixtures.clock
import dev.zilath.verifier.trust.FederationFixtures.credentialIssuerSection
import dev.zilath.verifier.trust.FederationFixtures.inputFor
import dev.zilath.verifier.trust.FederationFixtures.intermediatedChain
import dev.zilath.verifier.trust.FederationFixtures.leafConfiguration
import dev.zilath.verifier.trust.FederationFixtures.trustedKeyIds
import dev.zilath.verifier.trust.FederationFixtures.untrustedReason
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * OID-FED 1.0 §6.2: every subordinate statement's `constraints` apply, and a chain that
 * breaks any of them is invalid — offline, from a provided chain, and online, from a
 * resolved one.
 */
class ConstraintsTest {
    private val issuerKid = TestVectors.issuerEcKey.keyID

    private fun directChain(constraints: Map<String, Any?>) =
        listOf(leafConfiguration(), anchorStatementAboutLeaf { claim("constraints", constraints) })

    private fun decide(chain: List<String>) = chainEvaluator().evaluate(inputFor(trustChain = chain))

    private fun resolveOnline(fetcher: FederationFetcher) =
        FederationTrustEvaluator(FederationFixtures.anchorConfig(), fetcher, clock).evaluate(inputFor())

    @Test
    fun `max_path_length bounds the intermediates below the statement that sets it`() {
        val limitedAnchor = { limit: Long ->
            intermediatedChain(configureAnchorStatement = { claim("constraints", mapOf("max_path_length" to limit)) })
        }
        // One intermediate between the anchor and the leaf: 0 forbids it, 1 allows it.
        assertThat(untrustedReason(decide(limitedAnchor(0)))).contains("max_path_length")
        assertThat(trustedKeyIds(decide(limitedAnchor(1)))).containsExactly(issuerKid)
        // The production shape: the anchor's statement about its direct subordinate says 0.
        assertThat(trustedKeyIds(decide(directChain(mapOf("max_path_length" to 0))))).containsExactly(issuerKid)
        // An intermediate's own limit counts from itself: 0 still lets it vouch for the leaf.
        val limitedIntermediate =
            intermediatedChain(configureIntermediateStatement = { claim("constraints", mapOf("max_path_length" to 0)) })
        assertThat(trustedKeyIds(decide(limitedIntermediate))).containsExactly(issuerKid)
    }

    @Test
    fun `a malformed constraint fails the chain instead of being skipped`() {
        val malformed =
            listOf(
                mapOf("max_path_length" to -5),
                mapOf("max_path_length" to "1"),
                mapOf("max_path_length" to 1.5),
                mapOf("naming_constraints" to listOf(".example")),
                mapOf("naming_constraints" to mapOf("permitted" to ".example")),
                mapOf("allowed_entity_types" to "openid_credential_issuer"),
                mapOf("allowed_leaf_entity_types" to listOf(1)),
            )
        for (constraints in malformed) {
            assertThat(untrustedReason(decide(directChain(constraints))))
                .describedAs(constraints.toString())
                .contains("malformed constraints")
        }
        // Members this library does not know are ignored, as §6.2 allows.
        assertThat(trustedKeyIds(decide(directChain(mapOf("something_new" to true))))).containsExactly(issuerKid)
    }

    @Test
    fun `naming_constraints bind the leaf, excluded winning over permitted`() {
        fun naming(vararg members: Pair<String, List<String>>) = mapOf("naming_constraints" to mapOf(*members))
        // The leaf is https://issuer.example.
        val outside = "an entity is outside a superior's naming constraints"
        assertThat(
            untrustedReason(decide(directChain(naming("permitted" to listOf(".good.example"))))),
        ).contains(outside)
        assertThat(
            untrustedReason(decide(directChain(naming("excluded" to listOf("issuer.example"))))),
        ).contains(outside)
        assertThat(
            untrustedReason(
                decide(directChain(naming("permitted" to listOf(".example"), "excluded" to listOf("ISSUER.example")))),
            ),
        ).contains(outside)
        // A leading period is a domain: it admits hosts below it, never the name itself.
        assertThat(
            untrustedReason(decide(directChain(naming("permitted" to listOf(".issuer.example"))))),
        ).contains(outside)
        assertThat(untrustedReason(decide(directChain(naming("permitted" to emptyList()))))).contains(outside)
        assertThat(
            trustedKeyIds(decide(directChain(naming("permitted" to listOf(".example"))))),
        ).containsExactly(issuerKid)
        assertThat(
            trustedKeyIds(decide(directChain(naming("permitted" to listOf("issuer.example"))))),
        ).containsExactly(issuerKid)
    }

    @Test
    fun `an anchor's naming_constraints also bind the intermediate below it`() {
        val excludingTheIntermediate =
            intermediatedChain(
                configureAnchorStatement = {
                    claim("constraints", mapOf("naming_constraints" to mapOf("excluded" to listOf("int.example"))))
                },
            )
        assertThat(untrustedReason(decide(excludingTheIntermediate))).contains("naming constraints")
    }

    @Test
    fun `an entity type the constraints do not allow contributes nothing, credential keys included`() {
        for (name in listOf("allowed_entity_types", "allowed_leaf_entity_types")) {
            val relyingPartyOnly = directChain(mapOf(name to listOf("openid_credential_verifier")))
            assertThat(
                untrustedReason(decide(relyingPartyOnly)),
            ).describedAs(name).contains("no credential signing keys")
            val issuerAllowed = directChain(mapOf(name to listOf("openid_credential_issuer")))
            assertThat(trustedKeyIds(decide(issuerAllowed))).describedAs(name).containsExactly(issuerKid)
        }
        // Constraints from different superiors intersect.
        val narrowedBelow =
            intermediatedChain(
                configureIntermediateStatement = {
                    claim(
                        "constraints",
                        mapOf(
                            "allowed_entity_types" to emptyList<String>(),
                        ),
                    )
                },
                configureAnchorStatement = {
                    claim("constraints", mapOf("allowed_entity_types" to listOf("openid_credential_issuer")))
                },
            )
        assertThat(untrustedReason(decide(narrowedBelow))).contains("no credential signing keys")
    }

    @Test
    fun `federation_entity survives any allowed_entity_types, and dropped types never see a policy`() {
        val metadata =
            mapOf(
                "federation_entity" to mapOf("organization_name" to "leaf"),
                "openid_credential_issuer" to credentialIssuerSection(),
                "wallet_provider" to mapOf("jwks" to mapOf("keys" to emptyList<Any>())),
            )
        val statement =
            parseStatement(
                anchorStatementAboutLeaf {
                    claim(
                        "constraints",
                        mapOf(
                            "allowed_entity_types" to listOf("wallet_provider"),
                        ),
                    )
                },
            )
        assertThat(withoutDisallowedEntityTypes(metadata, listOf(statement)).keys)
            .containsExactlyInAnyOrder("federation_entity", "wallet_provider")
    }

    @Test
    fun `constraints hold on a chain resolved online too`() {
        val maxPathZero =
            FederationFixtures.intermediatedFederation {
                claim(
                    "constraints",
                    mapOf("max_path_length" to 0),
                )
            }
        assertThat(untrustedReason(resolveOnline(maxPathZero))).contains("max_path_length")
        val issuersOnlyElsewhere =
            FederationFixtures.directFederation {
                claim("constraints", mapOf("allowed_entity_types" to listOf("openid_credential_verifier")))
            }
        assertThat(untrustedReason(resolveOnline(issuersOnlyElsewhere))).contains("no credential signing keys")
        val outsideNamespace =
            FederationFixtures.directFederation {
                claim("constraints", mapOf("naming_constraints" to mapOf("permitted" to listOf(".good.example"))))
            }
        assertThat(untrustedReason(resolveOnline(outsideNamespace))).contains("naming constraints")
    }
}
