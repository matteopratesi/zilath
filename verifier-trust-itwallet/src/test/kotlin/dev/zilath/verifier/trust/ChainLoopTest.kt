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
import dev.zilath.verifier.trust.FederationFixtures.anchorConfig
import dev.zilath.verifier.trust.FederationFixtures.anchorConfiguration
import dev.zilath.verifier.trust.FederationFixtures.anchorKey
import dev.zilath.verifier.trust.FederationFixtures.chainEvaluator
import dev.zilath.verifier.trust.FederationFixtures.clock
import dev.zilath.verifier.trust.FederationFixtures.credentialIssuerSection
import dev.zilath.verifier.trust.FederationFixtures.encode
import dev.zilath.verifier.trust.FederationFixtures.fetcherOf
import dev.zilath.verifier.trust.FederationFixtures.inputFor
import dev.zilath.verifier.trust.FederationFixtures.jwksClaim
import dev.zilath.verifier.trust.FederationFixtures.leafFederationKey
import dev.zilath.verifier.trust.FederationFixtures.signedStatement
import dev.zilath.verifier.trust.FederationFixtures.trustedKeyIds
import dev.zilath.verifier.trust.FederationFixtures.untrustedReason
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * OID-FED 1.0 §17.1: trust chains MUST NOT contain loops; §10.1: an authority hint leading
 * to a loop MUST NOT be used.
 *
 * A leaf directly under the anchor creates an entity of its own, F, names it first among
 * its authority hints, and has the two vouch for each other: the chain
 * `[L, F about L, L about F, anchor about L]` links, verifies and ends at the anchor. The
 * statement in position 1, whose metadata overrides the leaf's, is then F's — so the
 * metadata the anchor imposes in its own statement about L, here a pinned credential key,
 * silently disappears.
 */
class ChainLoopTest {
    private val loopEntity = "https://loop.example"
    private val loopKey = ECKeyGenerator(Curve.P_256).keyID("loop-fed").generate()
    private val pinned = ECKeyGenerator(Curve.P_256).keyID("pinned-by-the-anchor").generate()

    private val leafConfiguration =
        signedStatement(leafFederationKey, LEAF_ID, LEAF_ID) {
            claim("jwks", jwksClaim(leafFederationKey))
            claim("authority_hints", listOf(loopEntity, ANCHOR_ID))
            claim(
                "metadata",
                mapOf(
                    "openid_credential_issuer" to credentialIssuerSection(),
                    "federation_entity" to mapOf("federation_fetch_endpoint" to "$LEAF_ID/fetch"),
                ),
            )
        }
    private val loopConfiguration =
        signedStatement(loopKey, loopEntity, loopEntity) {
            claim("jwks", jwksClaim(loopKey))
            claim("authority_hints", listOf(LEAF_ID))
            claim("metadata", mapOf("federation_entity" to mapOf("federation_fetch_endpoint" to "$loopEntity/fetch")))
        }
    private val loopAboutLeaf =
        signedStatement(loopKey, loopEntity, LEAF_ID) { claim("jwks", jwksClaim(leafFederationKey)) }
    private val leafAboutLoop =
        signedStatement(leafFederationKey, LEAF_ID, loopEntity) { claim("jwks", jwksClaim(loopKey)) }
    private val anchorAboutLeaf =
        signedStatement(anchorKey, ANCHOR_ID, LEAF_ID) {
            claim("jwks", jwksClaim(leafFederationKey))
            claim("metadata", mapOf("openid_credential_issuer" to mapOf("jwks" to jwksClaim(pinned))))
        }
    private val loopChain = listOf(leafConfiguration, loopAboutLeaf, leafAboutLoop, anchorAboutLeaf)

    private val federation =
        fetcherOf(
            mapOf(
                "$LEAF_ID/.well-known/openid-federation" to leafConfiguration,
                "$loopEntity/.well-known/openid-federation" to loopConfiguration,
                "$loopEntity/fetch?sub=${encode(LEAF_ID)}" to loopAboutLeaf,
                "$LEAF_ID/fetch?sub=${encode(loopEntity)}" to leafAboutLoop,
                "$ANCHOR_ID/.well-known/openid-federation" to anchorConfiguration(),
                "$ANCHOR_ID/fetch?sub=${encode(LEAF_ID)}" to anchorAboutLeaf,
            ),
        )

    @Test
    fun `a provided chain that passes through the same entity twice is untrusted, before any fetch`() {
        val fetched = mutableListOf<String>()
        val recording =
            FederationFetcher { url ->
                fetched += url
                federation.fetch(url)
            }
        val offline = chainEvaluator()
        val online = FederationTrustEvaluator(anchorConfig(), recording, clock)
        for (evaluator in listOf(offline, online)) {
            assertThat(untrustedReason(evaluator.evaluate(inputFor(trustChain = loopChain)))).contains("loops back")
        }
        assertThat(fetched).isEmpty()
    }

    @Test
    fun `resolved from scratch the same federation is untrusted, never trusted for the leaf's own key`() {
        // The leaf's first hint is F, whose only hint leads back to the leaf: that hint is
        // not used, and the walk has nowhere left to go.
        val online = FederationTrustEvaluator(anchorConfig(), federation, clock)
        assertThat(untrustedReason(online.evaluate(inputFor()))).contains("no authority_hints leading")
    }

    @Test
    fun `a hint already on the path is skipped, not followed`() {
        // A genuine intermediate that lists the leaf among its own superiors, before the
        // anchor. Following that hint went round until the length cap; skipping it reaches
        // the anchor through the intermediate's next hint.
        val intermediate = FederationFixtures.INTERMEDIATE_ID
        val intermediateKey = FederationFixtures.intermediateKey
        val leaf = FederationFixtures.leafConfiguration(authorityHint = intermediate)
        val fetcher =
            fetcherOf(
                mapOf(
                    "$LEAF_ID/.well-known/openid-federation" to leaf,
                    "$intermediate/.well-known/openid-federation" to
                        signedStatement(intermediateKey, intermediate, intermediate) {
                            claim("jwks", jwksClaim(intermediateKey))
                            claim("authority_hints", listOf(LEAF_ID, ANCHOR_ID))
                            claim(
                                "metadata",
                                mapOf(
                                    "federation_entity" to mapOf("federation_fetch_endpoint" to "$intermediate/fetch"),
                                ),
                            )
                        },
                    "$intermediate/fetch?sub=${encode(LEAF_ID)}" to
                        signedStatement(
                            intermediateKey,
                            intermediate,
                            LEAF_ID,
                        ) { claim("jwks", jwksClaim(leafFederationKey)) },
                    "$ANCHOR_ID/.well-known/openid-federation" to anchorConfiguration(),
                    "$ANCHOR_ID/fetch?sub=${encode(intermediate)}" to
                        signedStatement(
                            anchorKey,
                            ANCHOR_ID,
                            intermediate,
                        ) { claim("jwks", jwksClaim(intermediateKey)) },
                ),
            )
        val online = FederationTrustEvaluator(anchorConfig(), fetcher, clock)
        assertThat(trustedKeyIds(online.evaluate(inputFor()))).containsExactly(TestVectors.issuerEcKey.keyID)
    }

    @Test
    fun `without the detour the same federation pins the anchor's key`() {
        // The control: the anchor's statement alone, as an honest chain carries it.
        val direct = listOf(leafConfiguration, anchorAboutLeaf)
        assertThat(
            trustedKeyIds(chainEvaluator().evaluate(inputFor(trustChain = direct))),
        ).containsExactly("pinned-by-the-anchor")
    }

    @Test
    fun `an honest two-level chain is still trusted`() {
        assertThat(trustedKeyIds(chainEvaluator().evaluate(inputFor(trustChain = FederationFixtures.offlineChain()))))
            .containsExactly(TestVectors.issuerEcKey.keyID)
    }
}
