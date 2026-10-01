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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import dev.zilath.verifier.core.TestVectors
import dev.zilath.verifier.trust.FederationFixtures.ANCHOR_ID
import dev.zilath.verifier.trust.FederationFixtures.LEAF_ID
import dev.zilath.verifier.trust.FederationFixtures.chainEvaluator
import dev.zilath.verifier.trust.FederationFixtures.clock
import dev.zilath.verifier.trust.FederationFixtures.credentialIssuerSection
import dev.zilath.verifier.trust.FederationFixtures.encode
import dev.zilath.verifier.trust.FederationFixtures.fetcherOf
import dev.zilath.verifier.trust.FederationFixtures.inputFor
import dev.zilath.verifier.trust.FederationFixtures.jwksClaim
import dev.zilath.verifier.trust.FederationFixtures.signedRsaStatement
import dev.zilath.verifier.trust.FederationFixtures.trustedKeyIds
import dev.zilath.verifier.trust.FederationFixtures.untrustedReason
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * The algorithms an entity statement may be signed with: ES256, ES384, ES512, PS256, PS384 and
 * PS512, the ones IT-Wallet 1.4.7 lists as MUST or RECOMMENDED (test ATT-004). The chain here
 * is RSA from the anchor down, the family with a listed and an unlisted choice. Every refusal
 * is paired with an acceptance of the same keys under a listed algorithm, so that what is
 * refused is the `alg` and nothing else: an RS256 signature under a good 2048-bit key
 * verifies mathematically, and was accepted before 1.4.7.
 */
class StatementAlgorithmTest {
    private val issuerKid = TestVectors.issuerEcKey.keyID
    private val anchorRsa = RSAKeyGenerator(2048).keyID("ta-rsa").generate()
    private val leafRsa = RSAKeyGenerator(2048).keyID("leaf-rsa").generate()
    private val rsaAnchor = TrustAnchorConfig(ANCHOR_ID, listOf(anchorRsa.toPublicJWK()))

    private val listed = listOf(JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512)
    private val unlisted = listOf(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512)

    private fun leafConfiguration(algorithm: JWSAlgorithm) =
        signedRsaStatement(leafRsa, LEAF_ID, LEAF_ID, algorithm) {
            claim("jwks", jwksClaim(leafRsa))
            claim("authority_hints", listOf(ANCHOR_ID))
            claim("metadata", mapOf("openid_credential_issuer" to credentialIssuerSection()))
        }

    private fun anchorStatementAboutLeaf(algorithm: JWSAlgorithm) =
        signedRsaStatement(anchorRsa, ANCHOR_ID, LEAF_ID, algorithm) { claim("jwks", jwksClaim(leafRsa)) }

    private fun anchorConfiguration(algorithm: JWSAlgorithm) =
        signedRsaStatement(anchorRsa, ANCHOR_ID, ANCHOR_ID, algorithm, anchorConfigurationClaims())

    private fun anchorConfigurationClaims(): JWTClaimsSet.Builder.() -> Unit =
        {
            claim("jwks", jwksClaim(anchorRsa))
            claim("metadata", mapOf("federation_entity" to mapOf("federation_fetch_endpoint" to "$ANCHOR_ID/fetch")))
        }

    private fun decide(chain: List<String>) = chainEvaluator(rsaAnchor).evaluate(inputFor(trustChain = chain))

    @Test
    fun `a chain signed with a listed algorithm is trusted`() {
        listed.forEach {
            val chain = listOf(leafConfiguration(it), anchorStatementAboutLeaf(it))
            assertThat(trustedKeyIds(decide(chain))).`as`(it.name).containsExactly(issuerKid)
        }
    }

    @Test
    fun `a leaf configuration signed RS256, RS384 or RS512 is refused under a key that verifies it`() {
        unlisted.forEach {
            val chain = listOf(leafConfiguration(it), anchorStatementAboutLeaf(JWSAlgorithm.PS256))
            assertThat(untrustedReason(decide(chain)))
                .`as`(it.name)
                .isEqualTo("the statement at chain position 0 is signed with an algorithm that is not accepted")
        }
    }

    @Test
    fun `a subordinate statement signed RS256, RS384 or RS512 is refused under a key that verifies it`() {
        unlisted.forEach {
            val chain = listOf(leafConfiguration(JWSAlgorithm.PS256), anchorStatementAboutLeaf(it))
            assertThat(untrustedReason(decide(chain)))
                .`as`(it.name)
                .isEqualTo("the statement at chain position 1 is signed with an algorithm that is not accepted")
        }
    }

    @Test
    fun `a closing anchor configuration is held to the list too`() {
        val offline = listOf(leafConfiguration(JWSAlgorithm.PS256), anchorStatementAboutLeaf(JWSAlgorithm.PS256))
        assertThat(trustedKeyIds(decide(offline + anchorConfiguration(JWSAlgorithm.PS256)))).containsExactly(issuerKid)
        unlisted.forEach {
            assertThat(untrustedReason(decide(offline + anchorConfiguration(it))))
                .`as`(it.name)
                .isEqualTo("the statement at chain position 2 is signed with an algorithm that is not accepted")
        }
    }

    @Test
    fun `the anchor's configuration signed with an unlisted algorithm is refused before its endpoint is used`() {
        for (algorithm in listed + unlisted) {
            val fetched = mutableListOf<String>()
            val fetcher =
                fetcherOf(
                    mapOf(
                        "$LEAF_ID/.well-known/openid-federation" to leafConfiguration(JWSAlgorithm.PS256),
                        "$ANCHOR_ID/.well-known/openid-federation" to anchorConfiguration(algorithm),
                        "$ANCHOR_ID/fetch?sub=${encode(LEAF_ID)}" to anchorStatementAboutLeaf(JWSAlgorithm.PS256),
                    ),
                ).let { served -> FederationFetcher { url -> served.fetch(url).also { fetched += url } } }
            val decision = FederationTrustEvaluator(rsaAnchor, fetcher, clock).evaluate(inputFor())
            if (algorithm in listed) {
                assertThat(trustedKeyIds(decision)).`as`(algorithm.name).containsExactly(issuerKid)
            } else {
                assertThat(untrustedReason(decision))
                    .`as`(algorithm.name)
                    .isEqualTo(
                        "the trust anchor's entity configuration is signed with an algorithm that is not accepted",
                    )
                assertThat(fetched).`as`(algorithm.name).noneMatch { it.contains("sub=") }
            }
        }
    }
}
