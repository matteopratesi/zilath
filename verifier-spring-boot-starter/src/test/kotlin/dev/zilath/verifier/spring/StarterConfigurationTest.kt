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
import dev.zilath.verifier.core.CredentialStatus
import dev.zilath.verifier.core.DisclosedClaims
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.TrustEvaluator
import dev.zilath.verifier.core.VerificationResult
import dev.zilath.verifier.openid4vp.DirectPostBody
import dev.zilath.verifier.openid4vp.FlowOutcome
import dev.zilath.verifier.openid4vp.PresentationRequest
import dev.zilath.verifier.openid4vp.StartedTransaction
import dev.zilath.verifier.openid4vp.VerificationFlow
import kotlinx.serialization.json.JsonObject
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/** What the starter builds from `zilath.openid4vp.*`, and what it refuses to start with. */
class StarterConfigurationTest {
    @Configuration(proxyBeanMethods = false)
    class ApplicationBeans {
        @Bean
        fun trustEvaluator(): TrustEvaluator = TrustEvaluator { TrustDecision.Untrusted("configuration test") }

        @Bean
        fun statusChecker(): StatusChecker = StatusChecker { _, _ -> CredentialStatus.UNKNOWN }

        @Bean
        fun scriptedVerifier(): ScriptedVerifier = ScriptedVerifier()
    }

    private val signingKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate()

    private val runner =
        ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(OpenId4VpAutoConfiguration::class.java))
            .withUserConfiguration(ApplicationBeans::class.java)
            .withPropertyValues(
                "zilath.openid4vp.client-id=https://rp.example",
                "zilath.openid4vp.request-uri-base=https://rp.example/openid4vp/request",
                "zilath.openid4vp.response-uri-base=https://rp.example/openid4vp/response",
                "zilath.openid4vp.request-signing-key-jwk=${signingKey.toJSONString()}",
            )

    @Test
    fun `without a response encryption key each transaction encrypts to a key of its own`() {
        runner.run { context ->
            assertThat(context).hasNotFailed()
            val flow = context.getBean(VerificationFlow::class.java)
            val published = List(2) { publishedEncryptionKeyOf(requestObjectOf(flow, start(flow))) }
            assertThat(published.map { it.keyID }).doesNotHaveDuplicates()
            assertThat(published.map { it.computeThumbprint() }).doesNotHaveDuplicates()
        }
    }

    @Test
    fun `a configured response encryption key is the fallback a response may be encrypted to`() {
        val staticKey = ECKeyGenerator(Curve.P_256).keyID("rp-enc").generate()
        runner
            .withPropertyValues("zilath.openid4vp.response-encryption-key-jwk=${staticKey.toJSONString()}")
            .run { context ->
                context.getBean(ScriptedVerifier::class.java).next =
                    VerificationResult.Verified(DisclosedClaims(JsonObject(emptyMap())))
                val flow = context.getBean(VerificationFlow::class.java)
                val started = start(flow)
                val response = encryptedResponseFor(requestObjectOf(flow, started), encryptTo = staticKey.toPublicJWK())
                val outcome =
                    flow
                        .handleWalletResponse(
                            started.id,
                            DirectPostBody(mapOf("response" to response)),
                        ).outcome
                assertThat(outcome).isInstanceOf(FlowOutcome.Verified::class.java)
            }
    }

    private fun start(flow: VerificationFlow): StartedTransaction =
        flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))

    private fun requestObjectOf(
        flow: VerificationFlow,
        started: StartedTransaction,
    ): String = checkNotNull(flow.requestJwtFor(started.id))
}
