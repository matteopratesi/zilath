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
import dev.zilath.verifier.core.CredentialStatus
import dev.zilath.verifier.core.IssuerTrustInput
import dev.zilath.verifier.core.RawPresentation
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TestVectors
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.VerificationContext
import dev.zilath.verifier.core.VerificationResult
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.ZoneOffset

class FederationTrustEvaluatorTest {
    private val clock = Clock.fixed(TestVectors.NOW, ZoneOffset.UTC)

    private fun evaluator(
        fetcher: FederationFetcher,
        anchor: TrustAnchorConfig = FederationFixtures.anchorConfig(),
    ) = FederationTrustEvaluator(anchor, fetcher, clock)

    private fun inputFor(
        issuer: String? = FederationFixtures.LEAF_ID,
        trustChain: List<String> = emptyList(),
    ) = IssuerTrustInput(issuer = issuer, keyId = null, certificateChain = emptyList(), trustChain = trustChain)

    private fun assertTrustedWithIssuerKey(decision: TrustDecision) {
        assertThat(decision).isInstanceOf(TrustDecision.Trusted::class.java)
        val keys = (decision as TrustDecision.Trusted).issuerKeys
        assertThat(keys.map { it.keyID }).containsExactly(TestVectors.issuerEcKey.keyID)
    }

    @Test
    fun `a metadata_policy on the anchor statement replaces the leaf credential keys`() {
        val policyKey =
            com.nimbusds.jose.jwk.gen
                .ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256)
                .keyID("policy-forced")
                .generate()
        val chain =
            listOf(
                FederationFixtures.leafConfiguration(),
                FederationFixtures.signedStatement(
                    FederationFixtures.anchorKey,
                    FederationFixtures.ANCHOR_ID,
                    FederationFixtures.LEAF_ID,
                ) {
                    claim("jwks", FederationFixtures.jwksClaim(FederationFixtures.leafFederationKey))
                    claim(
                        "metadata_policy",
                        mapOf(
                            "openid_credential_issuer" to
                                mapOf("jwks" to mapOf("value" to FederationFixtures.jwksClaim(policyKey))),
                        ),
                    )
                },
            )
        val decision =
            FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = chain))
        assertThat(decision).isInstanceOf(TrustDecision.Trusted::class.java)
        assertThat((decision as TrustDecision.Trusted).issuerKeys.map { it.keyID })
            .containsExactly("policy-forced")
    }

    @Test
    fun `a policy resolving the jwks to empty does not fall back to federation keys`() {
        val chain =
            listOf(
                FederationFixtures.leafConfiguration(),
                FederationFixtures.signedStatement(
                    FederationFixtures.anchorKey,
                    FederationFixtures.ANCHOR_ID,
                    FederationFixtures.LEAF_ID,
                ) {
                    claim("jwks", FederationFixtures.jwksClaim(FederationFixtures.leafFederationKey))
                    claim(
                        "metadata_policy",
                        mapOf(
                            "openid_credential_issuer" to
                                mapOf("jwks" to mapOf("value" to mapOf("keys" to emptyList<Any>()))),
                        ),
                    )
                },
            )
        val decision =
            FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = chain))
        assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
        assertThat((decision as TrustDecision.Untrusted).reason).contains("no credential signing keys")
    }

    @Test
    fun `the superior statement metadata overrides the leaf before key selection`() {
        val superiorKey =
            com.nimbusds.jose.jwk.gen
                .ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256)
                .keyID("superior-imposed")
                .generate()
        val chain =
            listOf(
                FederationFixtures.leafConfiguration(),
                FederationFixtures.signedStatement(
                    FederationFixtures.anchorKey,
                    FederationFixtures.ANCHOR_ID,
                    FederationFixtures.LEAF_ID,
                ) {
                    claim("jwks", FederationFixtures.jwksClaim(FederationFixtures.leafFederationKey))
                    claim(
                        "metadata",
                        mapOf(
                            "openid_credential_issuer" to
                                mapOf("jwks" to FederationFixtures.jwksClaim(superiorKey)),
                        ),
                    )
                },
            )
        val decision =
            FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = chain))
        assertThat(decision).isInstanceOf(TrustDecision.Trusted::class.java)
        assertThat((decision as TrustDecision.Trusted).issuerKeys.map { it.keyID })
            .containsExactly("superior-imposed")
    }

    @Test
    fun `an explicit null metadata_policy on a signed statement fails the chain`() {
        // Built from a raw JSON payload: the claims-set builder may drop null members,
        // and the whole point is a PRESENT "metadata_policy": null.
        val payload =
            """{"iss":"${FederationFixtures.ANCHOR_ID}","sub":"${FederationFixtures.LEAF_ID}",""" +
                FederationFixtures.rawValidityWindow() + "," +
                """"jwks":{"keys":[${FederationFixtures.leafFederationKey.toPublicJWK().toJSONString()}]},""" +
                """"metadata_policy":null}"""
        val chain =
            listOf(
                FederationFixtures.leafConfiguration(),
                FederationFixtures.signedRawStatement(FederationFixtures.anchorKey, payload),
            )
        val decision =
            FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = chain))
        assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
        assertThat((decision as TrustDecision.Untrusted).reason).contains("malformed")
    }

    @Test
    fun `a violated metadata_policy makes the chain untrusted`() {
        // The leaf IS a credential issuer and publishes its keys: the only thing wrong is
        // the parameter the anchor's policy makes essential. This test used to use a leaf
        // with no metadata at all, and passed only because policies were applied to entity
        // types the leaf does not publish — the very defect that rejected the production
        // IT-Wallet issuer.
        val chain =
            listOf(
                FederationFixtures.leafConfiguration(),
                FederationFixtures.anchorStatementAboutLeaf {
                    claim(
                        "metadata_policy",
                        mapOf("openid_credential_issuer" to mapOf("credential_endpoint" to mapOf("essential" to true))),
                    )
                },
            )
        val decision =
            FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = chain))
        assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
        assertThat((decision as TrustDecision.Untrusted).reason).contains("essential")
    }

    @Test
    fun `a policy for an entity type the leaf does not publish is not applied to it`() {
        // The shape of the production anchor's statement: one policy for several entity
        // types, some essential parameters under a type this leaf is not.
        val chain =
            listOf(
                FederationFixtures.leafConfiguration(),
                FederationFixtures.anchorStatementAboutLeaf {
                    claim(
                        "metadata_policy",
                        mapOf(
                            "openid_credential_issuer" to mapOf("jwks" to mapOf("essential" to true)),
                            "wallet_provider" to mapOf("jwks" to mapOf("essential" to true)),
                        ),
                    )
                },
            )
        val decision =
            FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = chain))
        assertTrustedWithIssuerKey(decision)
    }

    @Test
    fun `a superior cannot graft a credential issuer section onto a leaf that never claimed one`() {
        val grafted = ECKeyGenerator(Curve.P_256).keyID("grafted").generate()
        val chain =
            listOf(
                FederationFixtures.leafConfiguration(
                    metadata = mapOf("federation_entity" to mapOf("organization_name" to "Not an issuer")),
                ),
                FederationFixtures.anchorStatementAboutLeaf {
                    claim(
                        "metadata",
                        mapOf("openid_credential_issuer" to mapOf("jwks" to FederationFixtures.jwksClaim(grafted))),
                    )
                },
            )
        val decision =
            FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = chain))
        assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
        assertThat((decision as TrustDecision.Untrusted).reason).contains("no credential signing keys")
    }

    @Test
    fun `a leaf publishing a null parameter does not slip past its superior's policy`() {
        // One of the anchor's policy says the endpoint must be one value, and essential; the
        // leaf publishes an explicit null, which used to count as present for essential and
        // as absent for one_of.
        val leafKeys = FederationFixtures.jwksClaim(FederationFixtures.leafFederationKey)
        val issuerKeys = FederationFixtures.jwksClaim(TestVectors.issuerEcKey)
        val payload =
            """{"iss":"${FederationFixtures.LEAF_ID}","sub":"${FederationFixtures.LEAF_ID}",""" +
                FederationFixtures.rawValidityWindow() + "," +
                """"jwks":${com.nimbusds.jose.util.JSONObjectUtils.toJSONString(leafKeys)},""" +
                """"authority_hints":["${FederationFixtures.ANCHOR_ID}"],""" +
                """"metadata":{"openid_credential_issuer":{"credential_endpoint":null,""" +
                """"jwks":${com.nimbusds.jose.util.JSONObjectUtils.toJSONString(issuerKeys)}}}}"""
        val chain =
            listOf(
                FederationFixtures.signedRawStatement(FederationFixtures.leafFederationKey, payload),
                FederationFixtures.anchorStatementAboutLeaf {
                    claim(
                        "metadata_policy",
                        mapOf(
                            "openid_credential_issuer" to
                                mapOf(
                                    "credential_endpoint" to
                                        mapOf(
                                            "one_of" to listOf("https://issuer.example/credential"),
                                            "essential" to true,
                                        ),
                                ),
                        ),
                    )
                },
            )
        val decision = FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = chain))
        assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
        assertThat((decision as TrustDecision.Untrusted).reason).contains("is null")
    }

    @Test
    fun `an operator nobody declared critical does not deny the chain`() {
        val chain =
            listOf(
                FederationFixtures.leafConfiguration(),
                FederationFixtures.anchorStatementAboutLeaf {
                    claim(
                        "metadata_policy",
                        mapOf(
                            "openid_credential_issuer" to
                                mapOf("credential_endpoint" to mapOf("regexp" to "^https://")),
                            // The IT-Wallet 1.4.6 §6.9 example statement, for a type this leaf is not.
                            "openid_credential_verifier" to
                                mapOf(
                                    "vp_formats" to
                                        mapOf(
                                            "dc+sd-jwt" to
                                                mapOf(
                                                    "sd-jwt_alg_values" to listOf("ES256"),
                                                    "kb-jwt_alg_values" to listOf("ES256"),
                                                ),
                                        ),
                                ),
                        ),
                    )
                },
            )
        assertTrustedWithIssuerKey(
            FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = chain)),
        )
    }

    @Test
    fun `metadata_policy_crit naming an operator the library does not implement fails the chain`() {
        for (crit in listOf(listOf("regexp"), emptyList<String>(), "regexp")) {
            val chain =
                listOf(
                    FederationFixtures.leafConfiguration(),
                    FederationFixtures.anchorStatementAboutLeaf {
                        claim(
                            "metadata_policy",
                            mapOf(
                                "openid_credential_issuer" to mapOf("credential_endpoint" to mapOf("regexp" to ".*")),
                            ),
                        )
                        claim("metadata_policy_crit", crit)
                    },
                )
            val decision = FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = chain))
            assertThat(decision)
                .describedAs("metadata_policy_crit %s", crit)
                .isInstanceOf(TrustDecision.Untrusted::class.java)
            assertThat((decision as TrustDecision.Untrusted).reason).contains("metadata_policy")
        }
    }

    @Test
    fun `a statement listing critical claims fails the chain, whoever issued it`() {
        // OID-FED §3.2: each claim in crit MUST be understood, and this library
        // understands no extension. A superior making one mandatory must not be ignored.
        val criticalSubordinate =
            listOf(
                FederationFixtures.leafConfiguration(),
                FederationFixtures.anchorStatementAboutLeaf {
                    claim("crit", listOf("revocation_flag"))
                    claim("revocation_flag", true)
                },
            )
        val criticalLeaf =
            listOf(
                FederationFixtures.signedStatement(
                    FederationFixtures.leafFederationKey,
                    FederationFixtures.LEAF_ID,
                    FederationFixtures.LEAF_ID,
                ) {
                    claim("jwks", FederationFixtures.jwksClaim(FederationFixtures.leafFederationKey))
                    claim("metadata", mapOf("openid_credential_issuer" to FederationFixtures.credentialIssuerSection()))
                    claim("crit", listOf("some_extension"))
                    claim("some_extension", "x")
                },
                FederationFixtures.anchorStatementAboutLeaf(),
            )
        for (chain in listOf(criticalSubordinate, criticalLeaf)) {
            val decision = FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = chain))
            assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
            assertThat((decision as TrustDecision.Untrusted).reason).contains("critical claims")
        }
    }

    @Test
    fun `resolves and trusts a leaf directly under the anchor`() {
        val decision = evaluator(FederationFixtures.directFederation()).evaluate(inputFor())
        assertTrustedWithIssuerKey(decision)
    }

    @Test
    fun `resolves and trusts a leaf through an intermediate`() {
        val decision = evaluator(FederationFixtures.intermediatedFederation()).evaluate(inputFor())
        assertTrustedWithIssuerKey(decision)
    }

    @Test
    fun `a chain anchored to unknown keys is untrusted`() {
        val impostor = ECKeyGenerator(Curve.P_256).keyID("impostor").generate()
        val anchor = TrustAnchorConfig(FederationFixtures.ANCHOR_ID, listOf(impostor.toPublicJWK()))
        val decision = evaluator(FederationFixtures.directFederation(), anchor).evaluate(inputFor())
        assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
    }

    @Test
    fun `an expired statement is untrusted`() {
        val chain =
            listOf(
                FederationFixtures.leafConfiguration(),
                FederationFixtures.signedStatement(
                    FederationFixtures.anchorKey,
                    FederationFixtures.ANCHOR_ID,
                    FederationFixtures.LEAF_ID,
                    expiresInSeconds = -60,
                ) { claim("jwks", FederationFixtures.jwksClaim(FederationFixtures.leafFederationKey)) },
            )
        val decision = FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = chain))
        assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
    }

    @Test
    fun `broken iss-sub linking is untrusted`() {
        val chain =
            listOf(
                FederationFixtures.leafConfiguration(),
                FederationFixtures.signedStatement(
                    FederationFixtures.anchorKey,
                    FederationFixtures.ANCHOR_ID,
                    "https://someone-else.example",
                ) { claim("jwks", FederationFixtures.jwksClaim(FederationFixtures.leafFederationKey)) },
            )
        val decision = FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = chain))
        assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
    }

    @Test
    fun `a leaf configuration signed by the wrong key is untrusted`() {
        val rogueKey = ECKeyGenerator(Curve.P_256).keyID("rogue").generate()
        val chain =
            listOf(
                FederationFixtures.leafConfiguration(federationKey = rogueKey),
                FederationFixtures.signedStatement(
                    FederationFixtures.anchorKey,
                    FederationFixtures.ANCHOR_ID,
                    FederationFixtures.LEAF_ID,
                    // The anchor vouches for the honest federation key, not the rogue one.
                ) { claim("jwks", FederationFixtures.jwksClaim(FederationFixtures.leafFederationKey)) },
            )
        val decision = FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = chain))
        assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
    }

    @Test
    fun `a chain whose leaf does not match the credential issuer is untrusted`() {
        val decision =
            FederationFixtures
                .chainEvaluator()
                .evaluate(inputFor(issuer = "https://impostor.example", trustChain = FederationFixtures.offlineChain()))
        assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
    }

    @Test
    fun `an oversized provided chain is rejected before any signature work`() {
        val padded = List(10) { FederationFixtures.leafConfiguration() } + FederationFixtures.offlineChain()
        val decision = FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = padded))
        assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
        assertThat((decision as TrustDecision.Untrusted).reason).contains("longer than")
    }

    @Test
    fun `fetch failures degrade to untrusted`() {
        val decision = evaluator(FederationFetcher { error("boom") }).evaluate(inputFor())
        assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
    }

    @Test
    fun `a statement with the wrong typ is untrusted`() {
        val chain =
            listOf(
                FederationFixtures.signedStatement(
                    FederationFixtures.leafFederationKey,
                    FederationFixtures.LEAF_ID,
                    FederationFixtures.LEAF_ID,
                    typ = "JWT",
                ) { claim("jwks", FederationFixtures.jwksClaim(FederationFixtures.leafFederationKey)) },
                FederationFixtures.offlineChain()[1],
            )
        val decision = FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = chain))
        assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
    }

    @Test
    fun `a leaf without credential metadata is untrusted, not silently given its federation keys`() {
        // This test used to assert the opposite, and the opposite was a hole: falling back
        // to the leaf's federation keys turned a metadata_policy RESTRICTING
        // openid_credential_issuer.jwks into one that widened it, and let any leaf that
        // simply published no credential metadata sign credentials with the keys it uses
        // for entity statements. Federation keys attest; credential keys sign credentials.
        val chain =
            listOf(
                FederationFixtures.leafConfiguration(includeCredentialKeys = false),
                FederationFixtures.offlineChain()[1],
            )
        val decision = FederationFixtures.chainEvaluator().evaluate(inputFor(trustChain = chain))
        assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
    }

    @Test
    fun `an entity id that is not an https identifier is refused before any fetch`() {
        // iss is unverified at this point: without this the library would ask the
        // integrator's fetcher to dereference whatever an attacker put in a credential.
        var fetched = false
        val evaluator =
            evaluator(
                FederationFetcher {
                    fetched = true
                    error("should not be reached")
                },
            )
        val badIds =
            listOf(
                "file:///etc/passwd",
                "http://10.0.0.1:8080",
                // https alone does not make an address usable: userinfo and bare IPs are
                // the shapes a reach for something internal takes.
                "https://root@ta.example",
                "https://10.0.0.1",
                "https://[fd00::1]/x",
                "https://",
                "not a url",
            )
        for (bad in badIds) {
            val decision = evaluator.evaluate(inputFor(issuer = bad, trustChain = emptyList()))
            assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
        }
        assertThat(fetched).isFalse()
    }

    @Test
    fun `a poisoned federation_fetch_endpoint is refused before the fetcher sees it`() {
        // The endpoint comes from the still-unverified configuration of a superior: it
        // gets the same shape rules as an entity id, or the walk stops. Without this the
        // library would hand the integrator's fetcher whatever a chain document says.
        val poisoned =
            listOf(
                "file:///etc/passwd",
                "http://internal.example/fetch",
                "https://user@ta.example/fetch",
                "https://169.254.169.254/latest",
                // The forms the JVM resolver accepts that a dotted-quad pattern does not see:
                // decimal 127.0.0.1, decimal 169.254.0.2, and a four-digit first octet.
                "https://2130706433/fetch",
                "https://2851995650/fetch",
                "https://0177.0.0.1/fetch",
            )
        for (bad in poisoned) {
            val fetched = mutableListOf<String>()
            val fetcher =
                FederationFetcher { url ->
                    fetched += url
                    when (url) {
                        "${FederationFixtures.LEAF_ID}/.well-known/openid-federation" ->
                            FederationFixtures.leafConfiguration()
                        "${FederationFixtures.ANCHOR_ID}/.well-known/openid-federation" ->
                            FederationFixtures.anchorConfiguration(fetchEndpoint = bad)
                        else -> error("unexpected fetch of $url")
                    }
                }
            val decision = evaluator(fetcher).evaluate(inputFor())
            assertThat(decision).isInstanceOf(TrustDecision.Untrusted::class.java)
            assertThat(fetched).noneMatch { it.startsWith(bad) }
        }
    }

    @Test
    fun `the anchor's entity configuration is verified before its fetch endpoint is used`() {
        // Whoever answers for the anchor's well-known URL used to choose where the library
        // fetched the anchor's statement from: the configuration was never verified, and
        // the forgery surfaced only after the request to the attacker's host was made.
        val attacker = ECKeyGenerator(Curve.P_256).keyID(FederationFixtures.anchorKey.keyID).generate()
        val forgedEndpoint =
            FederationFixtures.signedStatement(attacker, FederationFixtures.ANCHOR_ID, FederationFixtures.ANCHOR_ID) {
                claim("jwks", FederationFixtures.jwksClaim(attacker))
                claim(
                    "metadata",
                    mapOf(
                        "federation_entity" to mapOf("federation_fetch_endpoint" to "https://attacker.example/fetch"),
                    ),
                )
            }
        // Forged even with the genuine endpoint: nothing in it is used unverified.
        val forgedGenuineEndpoint =
            FederationFixtures.signedStatement(attacker, FederationFixtures.ANCHOR_ID, FederationFixtures.ANCHOR_ID) {
                claim("jwks", FederationFixtures.jwksClaim(attacker))
                claim(
                    "metadata",
                    mapOf(
                        "federation_entity" to
                            mapOf("federation_fetch_endpoint" to "${FederationFixtures.ANCHOR_ID}/fetch"),
                    ),
                )
            }
        val expired =
            FederationFixtures.signedStatement(
                FederationFixtures.anchorKey,
                FederationFixtures.ANCHOR_ID,
                FederationFixtures.ANCHOR_ID,
                expiresInSeconds = -120,
            ) { claim("jwks", FederationFixtures.jwksClaim(FederationFixtures.anchorKey)) }
        for (anchorConfiguration in listOf(forgedEndpoint, forgedGenuineEndpoint)) {
            val fetched = mutableListOf<String>()
            val fetcher =
                FederationFetcher { url ->
                    fetched += url
                    when (url) {
                        "${FederationFixtures.LEAF_ID}/.well-known/openid-federation" ->
                            FederationFixtures
                                .leafConfiguration()
                        "${FederationFixtures.ANCHOR_ID}/.well-known/openid-federation" -> anchorConfiguration
                        else -> FederationFixtures.anchorStatementAboutLeaf()
                    }
                }
            val decision = evaluator(fetcher).evaluate(inputFor())
            assertThat(FederationFixtures.untrustedReason(decision)).contains("anchor's entity configuration")
            assertThat(fetched).hasSize(2).noneMatch { it.contains("attacker") || it.contains("sub=") }
        }
        val expiredFetcher =
            FederationFixtures.fetcherOf(
                mapOf(
                    "${FederationFixtures.LEAF_ID}/.well-known/openid-federation" to
                        FederationFixtures.leafConfiguration(),
                    "${FederationFixtures.ANCHOR_ID}/.well-known/openid-federation" to expired,
                ),
            )
        assertThat(
            FederationFixtures.untrustedReason(evaluator(expiredFetcher).evaluate(inputFor())),
        ).contains("expired")
    }

    @Test
    fun `a fetch endpoint with its own query gets sub appended, not a second question mark`() {
        val endpoint = "${FederationFixtures.ANCHOR_ID}/fetch?profile=itwallet"
        val fetcher =
            FederationFixtures.fetcherOf(
                mapOf(
                    "${FederationFixtures.LEAF_ID}/.well-known/openid-federation" to
                        FederationFixtures.leafConfiguration(),
                    "${FederationFixtures.ANCHOR_ID}/.well-known/openid-federation" to
                        FederationFixtures.anchorConfiguration(fetchEndpoint = endpoint),
                    "$endpoint&sub=${FederationFixtures.encode(FederationFixtures.LEAF_ID)}" to
                        FederationFixtures.signedStatement(
                            FederationFixtures.anchorKey,
                            FederationFixtures.ANCHOR_ID,
                            FederationFixtures.LEAF_ID,
                        ) { claim("jwks", FederationFixtures.jwksClaim(FederationFixtures.leafFederationKey)) },
                ),
            )
        assertTrustedWithIssuerKey(evaluator(fetcher).evaluate(inputFor()))
    }

    @Test
    fun `an SD-JWT VC verifies end to end against the federation`() {
        val context =
            VerificationContext(
                expectedNonce = TestVectors.NONCE,
                expectedAudiences = setOf(TestVectors.AUDIENCE),
                clock = clock,
                trustEvaluator = evaluator(FederationFixtures.directFederation()),
                statusChecker = StatusChecker { _, _ -> CredentialStatus.VALID },
            )
        val result =
            SdJwtVcCredentialVerifier()
                .verify(RawPresentation.SdJwtVcPresentation(TestVectors.vector()), context)
        assertThat(result).isInstanceOf(VerificationResult.Verified::class.java)
    }
}
