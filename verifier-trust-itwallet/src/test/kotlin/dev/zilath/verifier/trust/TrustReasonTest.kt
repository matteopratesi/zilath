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
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.trust.FederationFixtures.ANCHOR_ID
import dev.zilath.verifier.trust.FederationFixtures.LEAF_ID
import dev.zilath.verifier.trust.FederationFixtures.anchorKey
import dev.zilath.verifier.trust.FederationFixtures.anchorStatementAboutLeaf
import dev.zilath.verifier.trust.FederationFixtures.chainEvaluator
import dev.zilath.verifier.trust.FederationFixtures.credentialIssuerSection
import dev.zilath.verifier.trust.FederationFixtures.inputFor
import dev.zilath.verifier.trust.FederationFixtures.jwksClaim
import dev.zilath.verifier.trust.FederationFixtures.leafConfiguration
import dev.zilath.verifier.trust.FederationFixtures.leafFederationKey
import dev.zilath.verifier.trust.FederationFixtures.signedStatement
import dev.zilath.verifier.trust.FederationFixtures.untrustedReason
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * `Untrusted.reason` becomes the `detail` of a rejection and a line in the integrator's
 * log. Whatever an unauthenticated caller puts in a credential header or a federation
 * document — CR/LF to forge log lines, tens of kilobytes to flood them — must not reach it.
 */
class TrustReasonTest {
    /** A forged log line followed by 5000 characters, where an identifier would be. */
    private val hostile = "https://x.example/\r\n2026-09-25 WARN [forged] FORGED " + "A".repeat(5000)

    private fun assertFixedPhrase(decision: TrustDecision) {
        val reason = untrustedReason(decision)
        assertThat(reason).doesNotContain("FORGED")
        assertThat(reason.filter { it.isISOControl() }).isEmpty()
        assertThat(reason.length).isLessThan(MAX_REASON)
    }

    @Test
    fun `an unusable credential iss is not echoed`() {
        val evaluator =
            FederationTrustEvaluator(
                FederationFixtures.anchorConfig(),
                { error("unreachable") },
                FederationFixtures.clock,
            )
        assertFixedPhrase(evaluator.evaluate(inputFor(issuer = hostile + "A".repeat(20_000))))
    }

    @Test
    fun `identifiers read from unverified statements are not echoed`() {
        // The leaf is genuine, so the online refresh is attempted and finds the federation
        // unreachable; the chain it carries then decides, and names a hostile intermediate.
        val stranger = ECKeyGenerator(Curve.P_256).keyID("stranger").generate()
        val intermediateStatement =
            signedStatement(stranger, hostile, LEAF_ID) { claim("jwks", jwksClaim(leafFederationKey)) }
        val relabelledAnchor = ECKey.Builder(anchorKey).keyID("not-the-anchor-kid").build()
        val impostorWithAnchorKid = ECKeyGenerator(Curve.P_256).keyID(anchorKey.keyID).generate()
        val chains =
            listOf(
                // Ends somewhere else: the last issuer used to be quoted.
                listOf(leafConfiguration(), signedStatement(stranger, hostile, LEAF_ID)),
                // The anchor's statement about the intermediate has expired: its subject used
                // to be quoted.
                listOf(
                    leafConfiguration(),
                    intermediateStatement,
                    signedStatement(
                        anchorKey,
                        ANCHOR_ID,
                        hostile,
                        expiresInSeconds = -3600,
                        issuedAtOffsetSeconds = -7200,
                    ) {
                        claim("jwks", jwksClaim(stranger))
                    },
                ),
                // Signed under a kid the anchor does not have.
                listOf(
                    leafConfiguration(),
                    intermediateStatement,
                    signedStatement(relabelledAnchor, ANCHOR_ID, hostile) { claim("jwks", jwksClaim(stranger)) },
                ),
                // Signed by another key under the anchor's kid: "the signature of the
                // statement about <subject> does not verify", it used to say.
                listOf(
                    leafConfiguration(),
                    intermediateStatement,
                    signedStatement(impostorWithAnchorKid, ANCHOR_ID, hostile) { claim("jwks", jwksClaim(stranger)) },
                ),
            )
        for (chain in chains) {
            assertFixedPhrase(chainEvaluator().evaluate(inputFor(trustChain = chain)))
        }
    }

    @Test
    fun `names from a superior's policy are not echoed`() {
        val chain =
            listOf(
                leafConfiguration(
                    metadata = mapOf("openid_credential_issuer" to credentialIssuerSection(hostile to "leaf")),
                ),
                anchorStatementAboutLeaf {
                    claim(
                        "metadata_policy",
                        mapOf("openid_credential_issuer" to mapOf(hostile to mapOf("one_of" to listOf("anchor")))),
                    )
                },
            )
        assertFixedPhrase(chainEvaluator().evaluate(inputFor(trustChain = chain)))
    }

    @Test
    fun `a hostile authority hint met while resolving online is not echoed`() {
        val fetcher =
            FederationFixtures.fetcherOf(
                mapOf("$LEAF_ID/.well-known/openid-federation" to leafConfiguration(authorityHint = hostile)),
            )
        val decision =
            FederationTrustEvaluator(
                FederationFixtures.anchorConfig(),
                fetcher,
                FederationFixtures.clock,
            ).evaluate(inputFor())
        assertFixedPhrase(decision)
    }

    private companion object {
        const val MAX_REASON = 160
    }
}
