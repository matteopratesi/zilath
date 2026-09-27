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

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import dev.zilath.verifier.core.TestVectors
import dev.zilath.verifier.trust.FederationFixtures.ANCHOR_ID
import dev.zilath.verifier.trust.FederationFixtures.LEAF_ID
import dev.zilath.verifier.trust.FederationFixtures.anchorKey
import dev.zilath.verifier.trust.FederationFixtures.anchorStatementAboutLeaf
import dev.zilath.verifier.trust.FederationFixtures.chainEvaluator
import dev.zilath.verifier.trust.FederationFixtures.inputFor
import dev.zilath.verifier.trust.FederationFixtures.jwksClaim
import dev.zilath.verifier.trust.FederationFixtures.leafConfiguration
import dev.zilath.verifier.trust.FederationFixtures.leafConfigurationWith
import dev.zilath.verifier.trust.FederationFixtures.leafFederationKey
import dev.zilath.verifier.trust.FederationFixtures.signedStatement
import dev.zilath.verifier.trust.FederationFixtures.trustedKeyIds
import dev.zilath.verifier.trust.FederationFixtures.untrustedReason
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/** OID-FED 1.0 §4: which statements a trust chain is made of, and where each may sit. */
class ChainShapeTest {
    private fun decide(chain: List<String>) = chainEvaluator().evaluate(inputFor(trustChain = chain))

    /** Leaf -> [intermediates] intermediates -> anchor, as a `trust_chain` carries it. */
    private fun chainThrough(intermediates: Int): List<String> {
        val ids = List(intermediates) { "https://int${it + 1}.example" }
        val keys = List(intermediates) { ECKeyGenerator(Curve.P_256).keyID("int${it + 1}-fed").generate() }
        val issuers = ids + ANCHOR_ID
        val signers = keys + anchorKey
        val subjects = listOf(LEAF_ID) + ids
        val subjectKeys = listOf(leafFederationKey) + keys
        return listOf(leafConfiguration(authorityHint = issuers.first())) +
            issuers.indices.map { level ->
                signedStatement(signers[level], issuers[level], subjects[level]) {
                    claim("jwks", jwksClaim(subjectKeys[level]))
                }
            }
    }

    @Test
    fun `a trust_chain header does not excuse a credential without iss`() {
        // The online path always refused it; the offline path compared the leaf with the
        // issuer only when there was one, and trusted any leaf of the federation.
        val withoutIss = inputFor(issuer = null, trustChain = FederationFixtures.offlineChain())
        val decision = chainEvaluator().evaluate(withoutIss)
        assertThat(untrustedReason(decision)).contains("no iss")
    }

    @Test
    fun `the leaf's superior in the chain must be one of its authority hints`() {
        // OID-FED §3.2: otherwise "the Federation graph is not well-formed". The anchor does
        // vouch for the leaf here, but the leaf names another superior.
        val elsewhere = leafConfiguration(authorityHint = FederationFixtures.INTERMEDIATE_ID)
        assertThat(untrustedReason(decide(listOf(elsewhere, anchorStatementAboutLeaf())))).contains("authority_hints")
    }

    @Test
    fun `the anchor's own configuration at the end of a chain must carry its jwks`() {
        // §3.2 requires the claim of every entity statement, although this one's is not used.
        val withoutJwks = signedStatement(anchorKey, ANCHOR_ID, ANCHOR_ID)
        assertThat(untrustedReason(decide(FederationFixtures.offlineChain() + withoutJwks)))
            .contains("carries no federation keys")
    }

    @Test
    fun `a closing anchor configuration must be the anchor's, although nothing in it is used`() {
        // §10.2: the last statement's signature validates with a key of the trust anchor. A
        // refreshed chain leaves the closing configuration out, so this is checked with the
        // shape, before any fetch.
        val impostor = ECKeyGenerator(Curve.P_256).keyID(anchorKey.keyID).generate()
        val forged = signedStatement(impostor, ANCHOR_ID, ANCHOR_ID) { claim("jwks", jwksClaim(impostor)) }
        assertThat(untrustedReason(decide(FederationFixtures.offlineChain() + forged))).contains("does not verify")
    }

    @Test
    fun `a subordinate statement carrying claims only an entity configuration may is malformed`() {
        // OID-FED §3.2: authority_hints, trust_anchor_hints and the trust mark claims make the
        // statement an entity configuration's; a superior's statement with them is malformed.
        val configurationOnly =
            listOf(
                "authority_hints" to listOf(ANCHOR_ID),
                "trust_anchor_hints" to listOf(ANCHOR_ID),
                "trust_marks" to emptyList<Any>(),
                "trust_mark_issuers" to emptyMap<String, Any>(),
                "trust_mark_owners" to emptyMap<String, Any>(),
            )
        for ((name, value) in configurationOnly) {
            val statement = anchorStatementAboutLeaf { claim(name, value) }
            assertThat(untrustedReason(decide(listOf(leafConfiguration(), statement))))
                .describedAs(name)
                .contains("only an entity configuration may")
        }
    }

    @Test
    fun `the leaf's configuration must verify with a key of its own jwks too`() {
        // §10.2: ES[0]'s signature validates with a key in ES[0]["jwks"], besides the one its
        // superior attests. Here the anchor attests the signing key, the leaf publishes another.
        val published = ECKeyGenerator(Curve.P_256).keyID("published-by-the-leaf").generate()
        val leaf =
            signedStatement(leafFederationKey, LEAF_ID, LEAF_ID) {
                claim("jwks", jwksClaim(published))
                claim("authority_hints", listOf(ANCHOR_ID))
                claim("metadata", mapOf("openid_credential_issuer" to FederationFixtures.credentialIssuerSection()))
            }
        assertThat(untrustedReason(decide(listOf(leaf, anchorStatementAboutLeaf())))).contains("kid")
    }

    @Test
    fun `a duplicated leaf cannot stand in for its own immediate superior`() {
        // [leaf, leaf, anchor's statement] links and verifies: the anchor's statement
        // attests the leaf's key, which signs both copies. It used to make the leaf its
        // own "immediate superior", so the metadata the anchor imposed simply vanished.
        val imposed = ECKeyGenerator(Curve.P_256).keyID("superior-imposed").generate()
        val anchorStatement =
            anchorStatementAboutLeaf {
                claim("metadata", mapOf("openid_credential_issuer" to mapOf("jwks" to jwksClaim(imposed))))
            }

        assertThat(
            trustedKeyIds(decide(listOf(leafConfiguration(), anchorStatement))),
        ).containsExactly("superior-imposed")
        assertThat(untrustedReason(decide(listOf(leafConfiguration(), leafConfiguration(), anchorStatement))))
            .contains("not a subordinate statement")
    }

    @Test
    fun `an entity configuration carrying a superior's directives is malformed`() {
        // OID-FED §3.2: metadata_policy, metadata_policy_crit and constraints belong to
        // subordinate statements. On the leaf they used to be ignored, on a trailing anchor
        // configuration applied.
        val directives =
            listOf(
                "metadata_policy" to mapOf("openid_credential_issuer" to mapOf("jwks" to mapOf("essential" to true))),
                "metadata_policy_crit" to listOf("regexp"),
                "constraints" to mapOf("max_path_length" to 0),
                "source_endpoint" to "$ANCHOR_ID/fetch",
            )
        for ((name, value) in directives) {
            val onTheLeaf = listOf(leafConfigurationWith { claim(name, value) }, anchorStatementAboutLeaf())
            val onTheAnchorConfiguration =
                listOf(
                    leafConfiguration(),
                    anchorStatementAboutLeaf(),
                    signedStatement(anchorKey, ANCHOR_ID, ANCHOR_ID) {
                        claim("jwks", jwksClaim(anchorKey))
                        claim(name, value)
                    },
                )
            for (chain in listOf(onTheLeaf, onTheAnchorConfiguration)) {
                assertThat(
                    untrustedReason(decide(chain)),
                ).describedAs(name).contains("only a subordinate statement may")
            }
        }
    }

    @Test
    fun `a chain closed by the anchor's own configuration is trusted like one without it`() {
        // OID-FED §4 makes the anchor's configuration an optional last element; IT-Wallet
        // chains that include it must not be denied.
        val chain = FederationFixtures.offlineChain() + FederationFixtures.anchorConfiguration()
        assertThat(trustedKeyIds(decide(chain))).containsExactly(dev.zilath.verifier.core.TestVectors.issuerEcKey.keyID)
    }

    @Test
    fun `a chain as long as allowed may still close with the anchor's own configuration`() {
        // Four statements by default, a leaf under two intermediates: the closing configuration
        // is not one of them, as it is not online, where resolution never fetches it into the chain.
        val longest = chainThrough(intermediates = 2)
        assertThat(trustedKeyIds(decide(longest))).containsExactly(TestVectors.issuerEcKey.keyID)
        assertThat(trustedKeyIds(decide(longest + FederationFixtures.anchorConfiguration())))
            .containsExactly(TestVectors.issuerEcKey.keyID)
    }

    @Test
    fun `the anchor's own configuration does not make room for one more statement`() {
        val tooLong = chainThrough(intermediates = 3)
        assertThat(untrustedReason(decide(tooLong))).contains("longer than 4 statements")
        assertThat(untrustedReason(decide(tooLong + FederationFixtures.anchorConfiguration())))
            .contains("longer than 4 statements")
    }

    @Test
    fun `behind the anchor's own configuration its statement is still checked against the configured keys`() {
        // The configuration is signed by the configured key but publishes another one; the
        // anchor's statement is signed with that other key. §4: the out-of-band keys verify
        // both, and what the configuration says about itself does not replace them. The
        // other key even reuses the configured kid, so only the key material tells them apart.
        val unconfigured = ECKeyGenerator(Curve.P_256).keyID(anchorKey.keyID).generate()
        val chain =
            listOf(
                leafConfiguration(),
                signedStatement(unconfigured, ANCHOR_ID, LEAF_ID) { claim("jwks", jwksClaim(leafFederationKey)) },
                signedStatement(anchorKey, ANCHOR_ID, ANCHOR_ID) { claim("jwks", jwksClaim(unconfigured)) },
            )
        assertThat(untrustedReason(decide(chain))).contains("does not verify")
    }
}
