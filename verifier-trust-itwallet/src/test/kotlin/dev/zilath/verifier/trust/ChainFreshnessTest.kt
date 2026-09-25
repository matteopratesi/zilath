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
import dev.zilath.verifier.trust.FederationFixtures.INTERMEDIATE_ID
import dev.zilath.verifier.trust.FederationFixtures.LEAF_ID
import dev.zilath.verifier.trust.FederationFixtures.anchorConfig
import dev.zilath.verifier.trust.FederationFixtures.anchorConfiguration
import dev.zilath.verifier.trust.FederationFixtures.anchorKey
import dev.zilath.verifier.trust.FederationFixtures.anchorStatementAboutLeaf
import dev.zilath.verifier.trust.FederationFixtures.clock
import dev.zilath.verifier.trust.FederationFixtures.encode
import dev.zilath.verifier.trust.FederationFixtures.inputFor
import dev.zilath.verifier.trust.FederationFixtures.intermediateConfiguration
import dev.zilath.verifier.trust.FederationFixtures.intermediatedChain
import dev.zilath.verifier.trust.FederationFixtures.jwksClaim
import dev.zilath.verifier.trust.FederationFixtures.leafConfiguration
import dev.zilath.verifier.trust.FederationFixtures.leafFederationKey
import dev.zilath.verifier.trust.FederationFixtures.offlineChain
import dev.zilath.verifier.trust.FederationFixtures.signedStatement
import dev.zilath.verifier.trust.FederationFixtures.trustedKeyIds
import dev.zilath.verifier.trust.FederationFixtures.unreachable
import dev.zilath.verifier.trust.FederationFixtures.untrustedReason
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.junit.jupiter.api.Test
import java.time.Duration

/**
 * A `trust_chain` header is frozen when the credential is issued. The federation's answer
 * today is what decides — IT-Wallet 1.4.6 §6.9, §6.12.1 — and the header stands in for it
 * only in offline-fallback mode, only while the federation cannot be reached.
 */
class ChainFreshnessTest {
    private val issuerKid = TestVectors.issuerEcKey.keyID
    private val wellKnownLeaf = "$LEAF_ID/.well-known/openid-federation"
    private val wellKnownAnchor = "$ANCHOR_ID/.well-known/openid-federation"
    private val anchorFetchAboutLeaf = "$ANCHOR_ID/fetch?sub=${encode(LEAF_ID)}"

    private val fetched = mutableListOf<String>()

    /** Serves [documents], records every request, and fails any other URL as unreachable. */
    private fun serving(vararg documents: Pair<String, () -> String>): FederationFetcher {
        val served = documents.toMap()
        return FederationFetcher { url ->
            fetched += url
            (served[url] ?: throw java.io.IOException("unreachable")).invoke()
        }
    }

    private fun evaluator(
        fetcher: FederationFetcher,
        offlineFallback: Boolean = false,
        maxStatementLifetime: Duration = Duration.ofHours(24),
    ) = FederationTrustEvaluator(
        anchorConfig(),
        fetcher,
        clock,
        offlineFallback = offlineFallback,
        maxStatementLifetime = maxStatementLifetime,
    )

    private fun withProvided(chain: List<String>) = inputFor(trustChain = chain)

    @Test
    fun `a provided chain is refreshed online and the fresh documents decide`() {
        // Since the credential was issued, the anchor started imposing another signing key.
        val rotated = ECKeyGenerator(Curve.P_256).keyID("rotated-by-the-anchor").generate()
        val fetcher =
            serving(
                wellKnownLeaf to { leafConfiguration() },
                wellKnownAnchor to { anchorConfiguration() },
                anchorFetchAboutLeaf to {
                    anchorStatementAboutLeaf {
                        claim("metadata", mapOf("openid_credential_issuer" to mapOf("jwks" to jwksClaim(rotated))))
                    }
                },
            )
        assertThat(trustedKeyIds(evaluator(fetcher).evaluate(withProvided(offlineChain()))))
            .containsExactly("rotated-by-the-anchor")
        assertThat(fetched).containsExactly(wellKnownLeaf, wellKnownAnchor, anchorFetchAboutLeaf)
    }

    @Test
    fun `a statement the superior no longer serves is a revocation, offline fallback or not`() {
        for (offlineFallback in listOf(false, true)) {
            val fetcher =
                serving(
                    wellKnownLeaf to { leafConfiguration() },
                    wellKnownAnchor to { anchorConfiguration() },
                    anchorFetchAboutLeaf to { throw FederationDocumentNotFoundException() },
                )
            val decision = evaluator(fetcher, offlineFallback).evaluate(withProvided(offlineChain()))
            assertThat(
                untrustedReason(decision),
            ).describedAs("offline fallback %s", offlineFallback).contains("does not publish")
        }
    }

    @Test
    fun `by default an unreachable federation is not papered over by the provided chain`() {
        assertThat(
            untrustedReason(evaluator(unreachable).evaluate(withProvided(offlineChain()))),
        ).contains("cannot fetch")
    }

    @Test
    fun `with offline fallback the provided chain decides only while the federation cannot be reached`() {
        val offline = evaluator(serving(), offlineFallback = true)
        assertThat(trustedKeyIds(offline.evaluate(withProvided(offlineChain())))).containsExactly(issuerKid)
        assertThat(
            fetched,
        ).describedAs("the whole refresh is still attempted").containsExactly(wellKnownLeaf, wellKnownAnchor)
        // An answer that comes back is final: here, the anchor's statement no longer verifies.
        val stranger = ECKeyGenerator(Curve.P_256).keyID(anchorKey.keyID).generate()
        val answering =
            serving(
                wellKnownLeaf to { leafConfiguration() },
                wellKnownAnchor to { anchorConfiguration() },
                anchorFetchAboutLeaf to {
                    signedStatement(stranger, ANCHOR_ID, LEAF_ID) { claim("jwks", jwksClaim(leafFederationKey)) }
                },
            )
        assertThat(untrustedReason(evaluator(answering, offlineFallback = true).evaluate(withProvided(offlineChain()))))
            .contains("does not verify")
    }

    @Test
    fun `with offline fallback a withdrawn leaf cannot hide its revocation behind its own configuration`() {
        // The leaf controls its own well-known URL: making it time out, or publishing a fresh
        // configuration whose only superior cannot be reached, used to count as an outage and
        // revive the header chain as it was. The superiors the header names are still asked,
        // and the anchor answers that it no longer vouches for the leaf.
        val withdrawn = { throw FederationDocumentNotFoundException() }
        val hiding =
            serving(
                wellKnownAnchor to { anchorConfiguration() },
                anchorFetchAboutLeaf to withdrawn,
            )
        val misdirecting =
            serving(
                wellKnownLeaf to { leafConfiguration(authorityHint = "https://unreachable.example") },
                wellKnownAnchor to { anchorConfiguration() },
                anchorFetchAboutLeaf to withdrawn,
            )
        for ((name, fetcher) in listOf("hiding" to hiding, "misdirecting" to misdirecting)) {
            val decision = evaluator(fetcher, offlineFallback = true).evaluate(withProvided(offlineChain()))
            assertThat(untrustedReason(decision)).describedAs(name).contains("does not publish")
        }
    }

    @Test
    fun `with offline fallback only an unreachable superior's statement is taken from the header`() {
        val (leaf, intermediateStatement, anchorStatement) = intermediatedChain()
        val wellKnownIntermediate = "$INTERMEDIATE_ID/.well-known/openid-federation"
        val intermediateFetchAboutLeaf = "$INTERMEDIATE_ID/fetch?sub=${encode(LEAF_ID)}"
        val anchorFetchAboutIntermediate = "$ANCHOR_ID/fetch?sub=${encode(INTERMEDIATE_ID)}"
        val provided = listOf(leaf, intermediateStatement, anchorStatement)
        // The intermediate is down, the anchor is not: the anchor's answer about the
        // intermediate still decides, here that it was withdrawn.
        val intermediateDown =
            serving(
                wellKnownLeaf to { leaf },
                wellKnownAnchor to { anchorConfiguration() },
                anchorFetchAboutIntermediate to { throw FederationDocumentNotFoundException() },
            )
        assertThat(
            untrustedReason(evaluator(intermediateDown, offlineFallback = true).evaluate(withProvided(provided))),
        ).contains("does not publish")
        // The anchor is down, the intermediate answers: its fresh statement is used, the
        // anchor's comes from the header.
        fetched.clear()
        val anchorDown =
            serving(
                wellKnownLeaf to { leaf },
                wellKnownIntermediate to { intermediateConfiguration() },
                intermediateFetchAboutLeaf to { intermediateStatement },
            )
        assertThat(trustedKeyIds(evaluator(anchorDown, offlineFallback = true).evaluate(withProvided(provided))))
            .containsExactly(issuerKid)
        assertThat(fetched).contains(intermediateFetchAboutLeaf, wellKnownAnchor)
    }

    @Test
    fun `an expired provided chain is resolved online instead of refused`() {
        val expired =
            listOf(
                leafConfiguration(),
                signedStatement(
                    anchorKey,
                    ANCHOR_ID,
                    LEAF_ID,
                    expiresInSeconds = -3600,
                    issuedAtOffsetSeconds = -7200,
                ) {
                    claim("jwks", jwksClaim(leafFederationKey))
                },
            )
        val online = evaluator(FederationFixtures.directFederation())
        assertThat(trustedKeyIds(online.evaluate(withProvided(expired)))).containsExactly(issuerKid)
        // Offline, with nothing fresher to be had, an expired chain is untrusted.
        assertThat(untrustedReason(evaluator(unreachable, offlineFallback = true).evaluate(withProvided(expired))))
            .contains("expired")
    }

    @Test
    fun `a provided chain of the wrong shape is refused before any fetch`() {
        val elsewhere =
            listOf(leafConfiguration(), signedStatement(anchorKey, "https://other-anchor.example", LEAF_ID))
        assertThat(untrustedReason(evaluator(serving()).evaluate(withProvided(elsewhere)))).contains("trust anchor")
        assertThat(fetched).isEmpty()
    }

    @Test
    fun `the refresh follows the superior the provided chain names among the leaf's hints`() {
        // The leaf lists an unrelated superior first; the chain it provides goes through the
        // intermediate. Resolving from scratch takes the first hint and gets nowhere.
        val twoHints =
            signedStatement(leafFederationKey, LEAF_ID, LEAF_ID) {
                claim("jwks", jwksClaim(leafFederationKey))
                claim("authority_hints", listOf("https://unrelated.example", INTERMEDIATE_ID))
                claim("metadata", mapOf("openid_credential_issuer" to FederationFixtures.credentialIssuerSection()))
            }
        val (_, intermediateStatement, anchorStatement) = intermediatedChain()
        val fetcher =
            serving(
                wellKnownLeaf to { twoHints },
                "$INTERMEDIATE_ID/.well-known/openid-federation" to { intermediateConfiguration() },
                "$INTERMEDIATE_ID/fetch?sub=${encode(LEAF_ID)}" to { intermediateStatement },
                wellKnownAnchor to { anchorConfiguration() },
                "$ANCHOR_ID/fetch?sub=${encode(INTERMEDIATE_ID)}" to { anchorStatement },
            )
        val provided = listOf(twoHints, intermediateStatement, anchorStatement)
        assertThat(trustedKeyIds(evaluator(fetcher).evaluate(withProvided(provided)))).containsExactly(issuerKid)
        assertThat(untrustedReason(evaluator(fetcher).evaluate(inputFor()))).contains("cannot fetch")
    }

    @Test
    fun `a subordinate statement may live 24 hours, an entity configuration longer`() {
        fun chainWithStatementLifetime(seconds: Long) =
            listOf(
                // A leaf configuration valid for a year, like the production issuer's.
                signedStatement(leafFederationKey, LEAF_ID, LEAF_ID, expiresInSeconds = YEAR - 600) {
                    claim("jwks", jwksClaim(leafFederationKey))
                    claim("authority_hints", listOf(ANCHOR_ID))
                    claim("metadata", mapOf("openid_credential_issuer" to FederationFixtures.credentialIssuerSection()))
                },
                signedStatement(anchorKey, ANCHOR_ID, LEAF_ID, expiresInSeconds = seconds - 600) {
                    claim("jwks", jwksClaim(leafFederationKey))
                },
            )
        val offline = evaluator(unreachable, offlineFallback = true)
        assertThat(
            trustedKeyIds(offline.evaluate(withProvided(chainWithStatementLifetime(DAY)))),
        ).containsExactly(issuerKid)
        assertThat(untrustedReason(offline.evaluate(withProvided(chainWithStatementLifetime(DAY + 3600)))))
            .contains("valid for longer")
        // The cap is the integrator's to lower, never to disable.
        val strict = evaluator(unreachable, offlineFallback = true, maxStatementLifetime = Duration.ofHours(1))
        assertThat(untrustedReason(strict.evaluate(withProvided(chainWithStatementLifetime(2 * 3600)))))
            .contains("valid for longer")
        assertThatIllegalArgumentException().isThrownBy { evaluator(unreachable, maxStatementLifetime = Duration.ZERO) }
    }

    private companion object {
        const val DAY = 86_400L
        const val YEAR = 365 * DAY
    }
}
