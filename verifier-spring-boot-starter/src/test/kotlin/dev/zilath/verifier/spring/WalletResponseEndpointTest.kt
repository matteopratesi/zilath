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
import dev.zilath.verifier.core.RejectionReason
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.TrustEvaluator
import dev.zilath.verifier.core.VerificationResult
import dev.zilath.verifier.openid4vp.FlowMode
import dev.zilath.verifier.openid4vp.PresentationRequest
import dev.zilath.verifier.openid4vp.StartedTransaction
import dev.zilath.verifier.openid4vp.VerificationFlow
import org.assertj.core.api.Assertions.assertThat
import org.hamcrest.Matchers.startsWith
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
import org.springframework.test.json.JsonCompareMode
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

/**
 * What the response endpoint answers the wallet and writes to the log, for each kind of
 * outcome. The verdict comes from a [ScriptedVerifier], so that each outcome is produced
 * through the real flow — request object, encrypted response, state — without building a
 * credential for it.
 */
@SpringBootTest(classes = [WalletResponseEndpointTest.TestApp::class])
@AutoConfigureMockMvc
class WalletResponseEndpointTest {
    // Auto-configuration only, no component scan: this package is the starter's own, and
    // scanning it would register the controllers without the conditions an application gets.
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    class TestApp {
        @Bean
        fun trustEvaluator(): TrustEvaluator = TrustEvaluator { TrustDecision.Untrusted("endpoint test") }

        @Bean
        fun statusChecker(): StatusChecker = StatusChecker { _, _ -> CredentialStatus.UNKNOWN }

        @Bean
        fun scriptedVerifier(): ScriptedVerifier = ScriptedVerifier()
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
            registry.add("zilath.openid4vp.same-device-callback-base") { "https://rp.example/cb" }
        }
    }

    @Autowired
    lateinit var mockMvc: MockMvc

    @Autowired
    lateinit var flow: VerificationFlow

    @Autowired
    lateinit var verifier: ScriptedVerifier

    @Test
    fun `a rejection detail reaches the log as one bounded line`() {
        // What a TrustEvaluator or CredentialVerifier of the application's may write into a
        // detail: here a forged log line, a line separator some viewers break on, and enough
        // text to flood the file.
        verifier.next =
            VerificationResult.Rejected(
                RejectionReason.UNTRUSTED_ISSUER,
                "https://evil.example/\r\n2026-09-04 WARN [forged] wallet response rejected: OK\u2028" +
                    "A".repeat(10_000),
            )
        val logged = capturingControllerLog { postPresentation(start()) }

        val line = logged.single { it.formattedMessage.startsWith("wallet response rejected") }.formattedMessage
        assertThat(line).doesNotContain("\r", "\n", "\u2028")
        assertThat(line).contains("UNTRUSTED_ISSUER", "https://evil.example/??2026-09-04")
        // The prefix, the reason, and at most 200 characters of the detail.
        assertThat(line.length).isLessThan(300)
    }

    @Test
    fun `a presentation failing its binding, nonce, audience, signature or issuer trust is 403`() {
        // IT-Wallet 1.4.6 §12.2.1.6.1: 403 invalid_request, one phrase for all of them.
        forbidden.forEach { reason ->
            verifier.next = VerificationResult.Rejected(reason, "detail for the log")
            postPresentation(start())
                .andExpect(status().isForbidden)
                .andExpectError("invalid_request", "the presentation was not accepted")
        }
    }

    @Test
    fun `a failure of the pipeline itself is 500 server_error`() {
        verifier.next = VerificationResult.Rejected(RejectionReason.INTERNAL_ERROR, "detail for the log")
        postPresentation(start())
            .andExpect(status().isInternalServerError)
            .andExpectError("server_error", "the wallet response could not be processed")
    }

    @Test
    fun `every other rejection is 400 invalid_request, with the same phrase`() {
        (RejectionReason.entries - forbidden - RejectionReason.INTERNAL_ERROR).forEach { reason ->
            verifier.next = VerificationResult.Rejected(reason, "detail for the log")
            postPresentation(start())
                .andExpect(status().isBadRequest)
                .andExpectError("invalid_request", "the wallet response is not valid")
        }
    }

    @Test
    fun `an unknown transaction is 404 with a JSON error`() {
        mockMvc
            .perform(
                post("/openid4vp/response/{txId}", "ghost")
                    .contentType("application/x-www-form-urlencoded")
                    .param("response", "whatever"),
            ).andExpect(status().isNotFound)
            .andExpectError("invalid_request", "unknown transaction")
    }

    @Test
    fun `only the first of two identical wallet errors is handed the return ticket`() {
        // access_denied is what every cancelling wallet sends: anyone who knows the
        // transaction id can post it too, after the wallet did, and must get an
        // acknowledgement and nothing else.
        val started = start(FlowMode.SAME_DEVICE)
        val first = postError(started, "access_denied")
        first
            .andExpect(status().isOk)
            .andExpect(
                jsonPath(
                    "$.redirect_uri",
                ).value(startsWith("https://rp.example/cb/${started.id.value}?response_code=")),
            ).andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
        postError(
            started,
            "access_denied",
        ).andExpect(status().isOk).andExpect(content().json("{}", JsonCompareMode.STRICT))
        postError(
            started,
            "server_error",
        ).andExpect(status().isOk).andExpect(content().json("{}", JsonCompareMode.STRICT))
    }

    /** The two members, and nothing that names the check or repeats the detail. */
    private fun ResultActions.andExpectError(
        error: String,
        description: String,
    ): ResultActions =
        andExpect(content().contentTypeCompatibleWith("application/json"))
            .andExpect(jsonPath("$.error").value(error))
            .andExpect(jsonPath("$.error_description").value(description))
            .andExpect(jsonPath("$.length()").value(2))

    private val forbidden =
        setOf(
            RejectionReason.INVALID_KEY_BINDING,
            RejectionReason.NONCE_MISMATCH,
            RejectionReason.AUDIENCE_MISMATCH,
            RejectionReason.UNTRUSTED_ISSUER,
            RejectionReason.INVALID_ISSUER_SIGNATURE,
        )

    private fun start(mode: FlowMode = FlowMode.CROSS_DEVICE): StartedTransaction =
        flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), mode)

    private fun postPresentation(started: StartedTransaction): ResultActions =
        mockMvc.perform(
            post("/openid4vp/response/{txId}", started.id.value)
                .contentType("application/x-www-form-urlencoded")
                .param("response", encryptedResponseFor(checkNotNull(flow.requestJwtFor(started.id)))),
        )

    private fun postError(
        started: StartedTransaction,
        error: String,
    ): ResultActions =
        mockMvc.perform(
            post("/openid4vp/response/{txId}", started.id.value)
                .contentType("application/x-www-form-urlencoded")
                .param("error", error),
        )
}
