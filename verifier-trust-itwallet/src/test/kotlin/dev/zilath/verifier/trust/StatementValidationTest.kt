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
    fun `a statement that attests no federation keys stops the chain instead of passing its own down`() {
        // A subordinate statement with an absent, empty or malformed jwks used to inherit
        // its superior's keys. The reason is asserted, not just the verdict: in a two-level
        // chain an inheriting verifier still fails later, for another reason.
        val noKeys = "carries no federation keys"
        val jwksVariants = listOf<Any?>(null, mapOf("keys" to emptyList<Any>()), "not-a-jwks")
        for (jwks in jwksVariants) {
            val statement = signedStatement(anchorKey, ANCHOR_ID, LEAF_ID) { if (jwks != null) claim("jwks", jwks) }
            assertThat(
                untrustedReason(decide(listOf(leafConfiguration(), statement))),
            ).describedAs("jwks %s", jwks).contains(noKeys)
        }
        // Three levels: the intermediate's statement about the leaf attests nothing, and the
        // leaf configuration is signed with the intermediate's own key — which an
        // inheriting verifier would have accepted.
        val chain =
            listOf(
                leafConfiguration(
                    authorityHint = FederationFixtures.INTERMEDIATE_ID,
                    federationKey = FederationFixtures.intermediateKey,
                ),
                signedStatement(FederationFixtures.intermediateKey, FederationFixtures.INTERMEDIATE_ID, LEAF_ID),
                signedStatement(anchorKey, ANCHOR_ID, FederationFixtures.INTERMEDIATE_ID) {
                    claim("jwks", jwksClaim(FederationFixtures.intermediateKey))
                },
            )
        assertThat(untrustedReason(decide(chain))).contains(noKeys)
    }

    @Test
    fun `a minute of clock skew is tolerated on both ends of a statement's validity`() {
        fun anchorStatement(
            issuedAt: Long,
            expiresIn: Long,
        ) = signedStatement(
            anchorKey,
            ANCHOR_ID,
            LEAF_ID,
            expiresInSeconds = expiresIn,
            issuedAtOffsetSeconds = issuedAt,
        ) { claim("jwks", jwksClaim(leafFederationKey)) }
        // Issued 30 s in our future, or expired 30 s ago: a peer's clock drift, accepted.
        assertThat(
            trustedKeyIds(decide(listOf(leafConfiguration(), anchorStatement(30, 3600)))),
        ).containsExactly(issuerKid)
        assertThat(
            trustedKeyIds(decide(listOf(leafConfiguration(), anchorStatement(-3600, -30)))),
        ).containsExactly(issuerKid)
        // Two minutes is no longer drift.
        assertThat(
            untrustedReason(decide(listOf(leafConfiguration(), anchorStatement(120, 3600)))),
        ).contains("not yet valid")
        assertThat(
            untrustedReason(decide(listOf(leafConfiguration(), anchorStatement(-3600, -120)))),
        ).contains("expired")
    }

    @Test
    fun `a federation key below 2048 RSA bits verifies nothing`() {
        // RFC 7518 §3.3. Nimbus refuses to generate such a key but verifies with one.
        for ((bits, trusted) in listOf(1024 to false, 2048 to true)) {
            val leafKey = FederationFixtures.rsaKey(bits, "leaf-rsa-$bits")
            val chain =
                listOf(
                    FederationFixtures.signedRsaStatement(leafKey, LEAF_ID, LEAF_ID) {
                        claim("jwks", jwksClaim(leafKey))
                        claim(
                            "metadata",
                            mapOf(
                                "openid_credential_issuer" to FederationFixtures.credentialIssuerSection(),
                            ),
                        )
                    },
                    signedStatement(anchorKey, ANCHOR_ID, LEAF_ID) { claim("jwks", jwksClaim(leafKey)) },
                )
            val decision = decide(chain)
            if (trusted) {
                assertThat(trustedKeyIds(decision)).describedAs("$bits bits").containsExactly(issuerKid)
            } else {
                assertThat(untrustedReason(decision)).describedAs("$bits bits").contains("does not verify")
            }
        }
        // A weak key configured for the anchor does not verify the anchor's statement either.
        val weakAnchor = FederationFixtures.rsaKey(1024, "ta-rsa-1024")
        val statement =
            FederationFixtures.signedRsaStatement(weakAnchor, ANCHOR_ID, LEAF_ID) {
                claim("jwks", jwksClaim(leafFederationKey))
            }
        val anchor = TrustAnchorConfig(ANCHOR_ID, listOf(weakAnchor.toPublicJWK()))
        assertThat(untrustedReason(decide(listOf(leafConfiguration(), statement), anchor))).contains("does not verify")
    }

    @Test
    fun `the entity statement typ is compared as a media type`() {
        // RFC 7515 §4.1.9: "application/" is implied, and case does not matter. The IT-Wallet
        // 1.4.6 §6.11 example chain uses the long form in every statement.
        for (typ in listOf("application/entity-statement+jwt", "Entity-Statement+JWT")) {
            val chain =
                listOf(
                    signedStatement(leafFederationKey, LEAF_ID, LEAF_ID, typ = typ) {
                        claim("jwks", jwksClaim(leafFederationKey))
                        claim(
                            "metadata",
                            mapOf(
                                "openid_credential_issuer" to FederationFixtures.credentialIssuerSection(),
                            ),
                        )
                    },
                    signedStatement(
                        anchorKey,
                        ANCHOR_ID,
                        LEAF_ID,
                        typ = typ,
                    ) { claim("jwks", jwksClaim(leafFederationKey)) },
                )
            assertThat(trustedKeyIds(decide(chain))).describedAs(typ).containsExactly(issuerKid)
        }
        // A different type, or none, is still not an entity statement.
        for (typ in listOf("JWT", "application/jwt", "application/entity-statement+jwt;v=1", null)) {
            val chain =
                listOf(
                    leafConfiguration(),
                    signedStatement(
                        anchorKey,
                        ANCHOR_ID,
                        LEAF_ID,
                        typ = typ,
                    ) { claim("jwks", jwksClaim(leafFederationKey)) },
                )
            assertThat(untrustedReason(decide(chain))).describedAs("typ %s", typ).contains("typ")
        }
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
