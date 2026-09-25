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
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import dev.zilath.verifier.core.TestVectors
import dev.zilath.verifier.trust.FederationFixtures.ANCHOR_ID
import dev.zilath.verifier.trust.FederationFixtures.LEAF_ID
import dev.zilath.verifier.trust.FederationFixtures.anchorKey
import dev.zilath.verifier.trust.FederationFixtures.chainEvaluator
import dev.zilath.verifier.trust.FederationFixtures.inputFor
import dev.zilath.verifier.trust.FederationFixtures.jwksClaim
import dev.zilath.verifier.trust.FederationFixtures.leafConfiguration
import dev.zilath.verifier.trust.FederationFixtures.leafFederationKey
import dev.zilath.verifier.trust.FederationFixtures.signedStatement
import dev.zilath.verifier.trust.FederationFixtures.trustedKeyIds
import dev.zilath.verifier.trust.FederationFixtures.untrustedReason
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.junit.jupiter.api.Test

/** What each entity statement of a chain must satisfy on its own: keys, kid, typ, time. */
class StatementValidationTest {
    private val issuerKid = TestVectors.issuerEcKey.keyID

    private fun decide(
        chain: List<String>,
        anchor: TrustAnchorConfig = FederationFixtures.anchorConfig(),
    ) = chainEvaluator(anchor).evaluate(inputFor(trustChain = chain))

    private fun anchorStatementSignedBy(signer: ECKey) =
        signedStatement(signer, ANCHOR_ID, LEAF_ID) { claim("jwks", jwksClaim(leafFederationKey)) }

    @Test
    fun `a statement is verified only with the key its kid names`() {
        // OID-FED 1.0 §3: the kid MUST be present and MUST exactly match a key of the set.
        val relabelled = ECKey.Builder(anchorKey).keyID("not-a-kid-of-the-anchor").build()
        assertThat(untrustedReason(decide(listOf(leafConfiguration(), anchorStatementSignedBy(relabelled)))))
            .contains("kid")
        val unlabelled = ECKey.Builder(anchorKey).keyID(null).build()
        assertThat(untrustedReason(decide(listOf(leafConfiguration(), anchorStatementSignedBy(unlabelled)))))
            .contains("no kid")
        // With two configured keys, the statement's kid picks the one that verifies it.
        val second = ECKeyGenerator(Curve.P_256).keyID("ta-fed-2").generate()
        val twoKeys = TrustAnchorConfig(ANCHOR_ID, listOf(anchorKey.toPublicJWK(), second.toPublicJWK()))
        assertThat(trustedKeyIds(decide(listOf(leafConfiguration(), anchorStatementSignedBy(second)), twoKeys)))
            .containsExactly(issuerKid)
    }

    @Test
    fun `every key a statement attests needs a unique kid`() {
        val twin = ECKeyGenerator(Curve.P_256).keyID(leafFederationKey.keyID).generate()
        val kidless = ECKey.Builder(ECKeyGenerator(Curve.P_256).generate()).keyID(null).build()
        for (extra in listOf(twin, kidless)) {
            val statement =
                signedStatement(anchorKey, ANCHOR_ID, LEAF_ID) { claim("jwks", jwksClaim(leafFederationKey, extra)) }
            assertThat(untrustedReason(decide(listOf(leafConfiguration(), statement))))
                .contains("without a unique kid")
        }
    }

    @Test
    fun `the same kid at two levels of a chain is not a collision`() {
        // Uniqueness is per key set: a leaf whose federation key reuses its anchor's kid is
        // still verified with the leaf key the anchor attests.
        val sameKidAsAnchor = ECKeyGenerator(Curve.P_256).keyID(anchorKey.keyID).generate()
        val chain =
            listOf(
                leafConfiguration(federationKey = sameKidAsAnchor),
                signedStatement(anchorKey, ANCHOR_ID, LEAF_ID) { claim("jwks", jwksClaim(sameKidAsAnchor)) },
            )
        assertThat(trustedKeyIds(decide(chain))).containsExactly(issuerKid)
    }

    @Test
    fun `the configured anchor keys need a unique kid each`() {
        assertThatIllegalArgumentException()
            .isThrownBy {
                TrustAnchorConfig(
                    ANCHOR_ID,
                    listOf(ECKey.Builder(anchorKey.toPublicJWK()).keyID(null).build()),
                )
            }
        val twin = ECKeyGenerator(Curve.P_256).keyID(anchorKey.keyID).generate()
        assertThatIllegalArgumentException()
            .isThrownBy { TrustAnchorConfig(ANCHOR_ID, listOf(anchorKey.toPublicJWK(), twin.toPublicJWK())) }
    }
}
