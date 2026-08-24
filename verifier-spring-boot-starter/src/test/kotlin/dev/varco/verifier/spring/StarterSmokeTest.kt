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
package dev.varco.verifier.spring

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import dev.varco.verifier.core.CredentialStatus
import dev.varco.verifier.core.StatusChecker
import dev.varco.verifier.core.TrustDecision
import dev.varco.verifier.core.TrustEvaluator
import dev.varco.verifier.openid4vp.FlowOutcome
import dev.varco.verifier.openid4vp.PresentationRequest
import dev.varco.verifier.openid4vp.VerificationFlow
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.context.annotation.Bean
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@SpringBootTest(classes = [StarterSmokeTest.TestApp::class])
@AutoConfigureMockMvc
class StarterSmokeTest {
    @SpringBootApplication
    class TestApp {
        @Bean
        fun trustEvaluator(): TrustEvaluator = TrustEvaluator { TrustDecision.Untrusted("smoke test") }

        @Bean
        fun statusChecker(): StatusChecker = StatusChecker { CredentialStatus.UNKNOWN }
    }

    companion object {
        private val signingKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate()
        private val encryptionKey = ECKeyGenerator(Curve.P_256).keyID("rp-enc").generate()

        @JvmStatic
        @DynamicPropertySource
        fun rpProperties(registry: DynamicPropertyRegistry) {
            registry.add("varco.openid4vp.client-id") { "https://rp.example" }
            registry.add("varco.openid4vp.request-uri-base") { "https://rp.example/openid4vp/request" }
            registry.add("varco.openid4vp.response-uri-base") { "https://rp.example/openid4vp/response" }
            registry.add("varco.openid4vp.request-signing-key-jwk") { signingKey.toJSONString() }
            registry.add("varco.openid4vp.response-encryption-key-jwk") { encryptionKey.toJSONString() }
        }
    }

    @Autowired
    lateinit var mockMvc: MockMvc

    @Autowired
    lateinit var flow: VerificationFlow

    private fun start() = flow.start(PresentationRequest.forTestPid("urn:varco:test:entitlement"))

    @Test
    fun `request endpoint serves the signed request object`() {
        val started = start()
        mockMvc
            .perform(get("/openid4vp/request/{txId}", started.id.value))
            .andExpect(status().isOk)
            .andExpect(content().contentTypeCompatibleWith("application/oauth-authz-req+jwt"))
    }

    @Test
    fun `request endpoint returns 404 for unknown transactions`() {
        mockMvc
            .perform(get("/openid4vp/request/{txId}", "ghost"))
            .andExpect(status().isNotFound)
    }

    @Test
    fun `response endpoint returns 404 for unknown transactions`() {
        mockMvc
            .perform(
                post("/openid4vp/response/{txId}", "ghost")
                    .contentType("application/x-www-form-urlencoded")
                    .param("response", "whatever"),
            ).andExpect(status().isNotFound)
    }

    @Test
    fun `a garbage response consumes the transaction with a 400`() {
        val started = start()
        mockMvc
            .perform(
                post("/openid4vp/response/{txId}", started.id.value)
                    .contentType("application/x-www-form-urlencoded")
                    .param("response", "not-a-jwe"),
            ).andExpect(status().isBadRequest)
        // Consumed: the request object is gone and a retry is a replay, still 400.
        mockMvc
            .perform(get("/openid4vp/request/{txId}", started.id.value))
            .andExpect(status().isNotFound)
        mockMvc
            .perform(
                post("/openid4vp/response/{txId}", started.id.value)
                    .contentType("application/x-www-form-urlencoded")
                    .param("response", "not-a-jwe"),
            ).andExpect(status().isBadRequest)
        assertThat(flow.awaitOutcome(started.id)).isInstanceOf(FlowOutcome.Rejected::class.java)
    }
}
