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

    @Test
    fun `a trust_chain header does not excuse a credential without iss`() {
        // The online path always refused it; the offline path compared the leaf with the
        // issuer only when there was one, and trusted any leaf of the federation.
        val withoutIss = inputFor(issuer = null, trustChain = FederationFixtures.offlineChain())
        val decision = chainEvaluator().evaluate(withoutIss)
        assertThat(untrustedReason(decision)).contains("no iss")
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
