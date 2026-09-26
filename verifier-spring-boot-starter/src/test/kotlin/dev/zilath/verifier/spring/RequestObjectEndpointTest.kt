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
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.TrustEvaluator
import dev.zilath.verifier.openid4vp.PresentationRequest
import dev.zilath.verifier.openid4vp.StartedTransaction
import dev.zilath.verifier.openid4vp.VerificationFlow
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

/** The request object by POST, `request_uri_method=post` (OpenID4VP 1.0 §5.10). */
@SpringBootTest(classes = [RequestObjectEndpointTest.TestApp::class])
@AutoConfigureMockMvc
class RequestObjectEndpointTest {
    // Auto-configuration only, no component scan: see StarterSmokeTest.
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    class TestApp {
        @Bean
        fun trustEvaluator(): TrustEvaluator = TrustEvaluator { TrustDecision.Untrusted("request object test") }

        @Bean
        fun statusChecker(): StatusChecker = StatusChecker { _, _ -> CredentialStatus.UNKNOWN }
    }

    companion object {
        private val signingKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate()

        @JvmStatic
        @DynamicPropertySource
        fun rpProperties(registry: DynamicPropertyRegistry) {
            registry.add("zilath.openid4vp.client-id") { "https://rp.example" }
            registry.add("zilath.openid4vp.request-uri-base") { "https://rp.example/openid4vp/request" }
            registry.add("zilath.openid4vp.response-uri-base") { "https://rp.example/openid4vp/response" }
            registry.add("zilath.openid4vp.request-signing-key-jwk") { signingKey.toJSONString() }
        }

        /** What a wallet may say about itself (OpenID4VP 1.0 §10), and must not find in a log. */
        private const val WALLET_METADATA =
            """{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"]}},"marker":"wallet-metadata-7f3a"}"""
    }

    @Autowired
    lateinit var mockMvc: MockMvc

    @Autowired
    lateinit var flow: VerificationFlow

    @Test
    fun `the QR payload announces the POST leg the starter serves`() {
        assertThat(start().qrPayload).endsWith("&request_uri_method=post")
    }

    @Test
    fun `a wallet asking by POST gets the request object with its wallet nonce`() {
        val started = start()
        val logged =
            capturingControllerLog {
                val body =
                    mockMvc
                        .perform(
                            post("/openid4vp/request/{txId}", started.id.value)
                                .contentType("application/x-www-form-urlencoded")
                                .accept("application/oauth-authz-req+jwt")
                                .param("wallet_metadata", WALLET_METADATA)
                                .param("wallet_nonce", "wallet-nonce-1"),
                        ).andExpect(status().isOk)
                        .andExpect(content().contentTypeCompatibleWith("application/oauth-authz-req+jwt"))
                        .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                        .andReturn()
                        .response.contentAsString
                val claims = SignedJWT.parse(body).jwtClaimsSet
                assertThat(claims.getStringClaim("wallet_nonce")).isEqualTo("wallet-nonce-1")
                assertThat(claims.getStringClaim("state")).isEqualTo(started.id.value)
            }
        assertThat(logged.map { it.formattedMessage }).noneMatch { "wallet-metadata-7f3a" in it }
    }

    @Test
    fun `a POST without parameters gets the request object without a wallet nonce`() {
        val started = start()
        val body =
            mockMvc
                .perform(
                    post(
                        "/openid4vp/request/{txId}",
                        started.id.value,
                    ).contentType("application/x-www-form-urlencoded"),
                ).andExpect(status().isOk)
                .andReturn()
                .response.contentAsString
        assertThat(SignedJWT.parse(body).jwtClaimsSet.claims).doesNotContainKey("wallet_nonce")
    }

    @Test
    fun `an oversized wallet nonce or wallet metadata is 400 invalid_request`() {
        val started = start()
        mockMvc
            .perform(
                post("/openid4vp/request/{txId}", started.id.value)
                    .contentType("application/x-www-form-urlencoded")
                    .param("wallet_nonce", "n".repeat(VerificationFlow.MAX_WALLET_NONCE_LENGTH + 1)),
            ).andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("invalid_request"))
            .andExpect(jsonPath("$.error_description").value("wallet_nonce is too long"))
        mockMvc
            .perform(
                post("/openid4vp/request/{txId}", started.id.value)
                    .contentType("application/x-www-form-urlencoded")
                    .param("wallet_metadata", "{" + " ".repeat(64 * 1024) + "}"),
            ).andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error_description").value("wallet_metadata is too large"))
        // Neither touched the transaction: its request object is still there.
        assertThat(flow.requestJwtFor(started.id)).isNotNull()
    }

    private fun start(): StartedTransaction = flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
}
