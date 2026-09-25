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
package dev.zilath.verifier.spring

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.CredentialStatus
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.TrustEvaluator
import dev.zilath.verifier.openid4vp.ArfBaselineProfile
import dev.zilath.verifier.openid4vp.PresentationRequest
import dev.zilath.verifier.openid4vp.RelyingPartyConfiguration
import dev.zilath.verifier.openid4vp.RpEndpoints
import dev.zilath.verifier.openid4vp.RpEntityConfiguration
import dev.zilath.verifier.openid4vp.RpFederationConfig
import dev.zilath.verifier.openid4vp.RpKeys
import dev.zilath.verifier.openid4vp.TrustChainSource
import dev.zilath.verifier.openid4vp.VerificationFlow
import dev.zilath.verifier.openid4vp.WalletProfile
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.assertj.AssertableApplicationContext
import org.springframework.core.env.MapPropertySource
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import java.time.Clock

/**
 * The starter as an `openid_federation:` relying party, which IT-Wallet 1.4.6 expects beside
 * `x509_hash:`. Before the fourth internal review it could be neither: no property reached
 * the federation configuration, so that client id failed the application at startup, and
 * nothing served the entity configuration a wallet resolves it through.
 */
class FederationConfigurationTest {
    private val signingKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate()
    private val federationKey = ECKeyGenerator(Curve.P_256).keyID("rp-fed").generate()

    private val federation =
        arrayOf(
            "zilath.openid4vp.client-id=openid_federation:https://rp.example",
            "zilath.openid4vp.federation.entity-id=https://rp.example",
            "zilath.openid4vp.federation.federation-key-jwk=${federationKey.toJSONString()}",
            "zilath.openid4vp.federation.authority-hints[0]=https://trust-anchor.example",
            "zilath.openid4vp.federation.organization-name=Teatro di Prova",
            "zilath.openid4vp.federation.contacts[0]=biglietteria@teatro.example",
        )

    @Test
    fun `an openid_federation client id without a federation fails, naming the properties to set`() {
        starterRunner(signingKey)
            .withPropertyValues("zilath.openid4vp.client-id=openid_federation:https://rp.example")
            .run { context ->
                assertThat(startupFailureOf(context))
                    .contains("openid_federation:", "zilath.openid4vp.federation.*", "entity-id", "contacts")
            }
    }

    @Test
    fun `a federation without contacts fails at startup`() {
        starterRunner(signingKey)
            .withPropertyValues(*federation.filterNot { "contacts" in it }.toTypedArray())
            .run { context ->
                assertThat(startupFailureOf(context)).contains("zilath.openid4vp.federation", "contacts")
            }
    }

    @Test
    fun `federation properties without an entity id fail rather than go unused`() {
        starterRunner(signingKey)
            .withPropertyValues("zilath.openid4vp.federation.contacts[0]=biglietteria@teatro.example")
            .run { context ->
                assertThat(startupFailureOf(context)).contains("without zilath.openid4vp.federation.entity-id")
            }
    }

    @Test
    fun `an x509_hash client id whose signing key carries no certificate fails at startup`() {
        starterRunner(signingKey)
            .withPropertyValues("zilath.openid4vp.client-id=x509_hash:bm90LWEtcmVhbC1oYXNo")
            .run { context ->
                assertThat(startupFailureOf(context)).contains("x509_hash", "x5c")
            }
    }

    @Test
    fun `an openid_federation relying party sends its client id and the chain it was given`() {
        val chain = listOf(entityConfigurationOfTheSameRelyingParty())
        starterRunner(signingKey)
            .withPropertyValues(*federation, "zilath.openid4vp.federation.trust-chain[0]=${chain.single()}")
            .run { context ->
                val config = context.getBean(RelyingPartyConfiguration::class.java)
                assertThat(config.federation!!.entityId).isEqualTo("https://rp.example")
                assertThat(config.federation!!.contacts).containsExactly("biglietteria@teatro.example")
                val requestObject = requestObjectOf(context)
                assertThat(requestObject.jwtClaimsSet.getStringClaim("client_id"))
                    .isEqualTo("openid_federation:https://rp.example")
                assertThat(requestObject.header.getCustomParam("trust_chain")).isEqualTo(chain)
            }
    }

    @Test
    fun `a trust chain source bean supplies the chain instead`() {
        val chain = listOf(entityConfigurationOfTheSameRelyingParty())
        starterRunner(signingKey)
            .withPropertyValues(*federation)
            .withBean(TrustChainSource::class.java, { TrustChainSource { chain } })
            .run { context ->
                assertThat(requestObjectOf(context).header.getCustomParam("trust_chain")).isEqualTo(chain)
            }
    }

    @Test
    fun `a wallet profile bean is the profile the flow speaks`() {
        starterRunner(signingKey).run { context ->
            assertThat(
                requestObjectOf(context).jwtClaimsSet.getStringClaim("response_mode"),
            ).isEqualTo("direct_post.jwt")
        }
        starterRunner(signingKey)
            .withBean(WalletProfile::class.java, { ArfBaselineProfile })
            .run { context ->
                assertThat(
                    requestObjectOf(context).jwtClaimsSet.getStringClaim("response_mode"),
                ).isEqualTo("direct_post")
            }
    }

    @Test
    fun `the entity configuration is served at the well-known path`() {
        webStarterRunner(signingKey).withPropertyValues(*federation).run { context ->
            val body =
                MockMvcBuilders
                    .webAppContextSetup(context)
                    .build()
                    .perform(get("/.well-known/openid-federation"))
                    .andExpect(status().isOk)
                    .andExpect(content().contentTypeCompatibleWith("application/entity-statement+jwt"))
                    .andReturn()
                    .response.contentAsString
            val statement = SignedJWT.parse(body)
            assertThat(statement.jwtClaimsSet.subject).isEqualTo("https://rp.example")
            assertThat(statement.jwtClaimsSet.issuer).isEqualTo("https://rp.example")
            assertThat(statement.header.keyID).isEqualTo("rp-fed")
            val entity = statement.jwtClaimsSet.getJSONObjectClaim("metadata")["federation_entity"] as Map<*, *>
            assertThat(entity["contacts"]).isEqualTo(listOf("biglietteria@teatro.example"))
        }
    }

    @Test
    fun `without a federation there is no entity configuration endpoint`() {
        webStarterRunner(signingKey).withPropertyValues("zilath.openid4vp.federation.entity-id=").run { context ->
            assertThat(context).hasNotFailed().doesNotHaveBean(OpenId4VpFederationController::class.java)
            MockMvcBuilders
                .webAppContextSetup(context)
                .build()
                .perform(get("/.well-known/openid-federation"))
                .andExpect(status().isNotFound)
        }
    }

    @Test
    fun `a blank entity id is no federation, as an empty one is`() {
        // Written as a property source: the test property helper would trim the blank away.
        starterRunner(signingKey)
            .withInitializer { context ->
                context.environment.propertySources.addFirst(
                    MapPropertySource("blank", mapOf("zilath.openid4vp.federation.entity-id" to "  ")),
                )
            }.run { context ->
                assertThat(context).hasNotFailed().doesNotHaveBean(OpenId4VpFederationController::class.java)
                assertThat(context.getBean(RelyingPartyConfiguration::class.java).federation).isNull()
            }
    }

    private fun requestObjectOf(context: AssertableApplicationContext): SignedJWT {
        val flow = context.getBean(VerificationFlow::class.java)
        val started = flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        return SignedJWT.parse(flow.requestJwtFor(started.id))
    }

    private fun startupFailureOf(context: AssertableApplicationContext): String {
        assertThat(context).hasFailed()
        return generateSequence(context.startupFailure) { it.cause }.mapNotNull { it.message }.joinToString(" | ")
    }

    /**
     * An entity configuration of `https://rp.example`, as the federation would hand back at
     * onboarding: what the first element of a trust chain for this relying party looks like.
     */
    private fun entityConfigurationOfTheSameRelyingParty(): String {
        val federationConfig =
            RpFederationConfig(
                entityId = "https://rp.example",
                federationKey = federationKey,
                authorityHints = listOf("https://trust-anchor.example"),
                organizationName = "Teatro di Prova",
                contacts = listOf("biglietteria@teatro.example"),
            )
        val config =
            RelyingPartyConfiguration(
                clientId = "openid_federation:https://rp.example",
                endpoints =
                    RpEndpoints(
                        "https://rp.example/openid4vp/request",
                        "https://rp.example/openid4vp/response",
                    ),
                keys = RpKeys(requestSigningKey = signingKey),
                trustEvaluator = TrustEvaluator { TrustDecision.Untrusted("unused") },
                statusChecker = { _, _ -> CredentialStatus.UNKNOWN },
                federation = federationConfig,
            )
        return RpEntityConfiguration.build(config, federationConfig, Clock.systemUTC())
    }
}
