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

import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
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
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.context.annotation.Bean
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post

/**
 * What the response endpoint answers the wallet and writes to the log, for each kind of
 * outcome. The verdict comes from a [ScriptedVerifier], so that each outcome is produced
 * through the real flow — request object, encrypted response, state — without building a
 * credential for it.
 */
@SpringBootTest(classes = [WalletResponseEndpointTest.TestApp::class])
@AutoConfigureMockMvc
class WalletResponseEndpointTest {
    @SpringBootApplication
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
        private val encryptionKey = ECKeyGenerator(Curve.P_256).keyID("rp-enc").generate()

        @JvmStatic
        @DynamicPropertySource
        fun rpProperties(registry: DynamicPropertyRegistry) {
            registry.add("zilath.openid4vp.client-id") { "https://rp.example" }
            registry.add("zilath.openid4vp.request-uri-base") { "https://rp.example/openid4vp/request" }
            registry.add("zilath.openid4vp.response-uri-base") { "https://rp.example/openid4vp/response" }
            registry.add("zilath.openid4vp.request-signing-key-jwk") { signingKey.toJSONString() }
            registry.add("zilath.openid4vp.response-encryption-key-jwk") { encryptionKey.toJSONString() }
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

    private fun start(mode: FlowMode = FlowMode.CROSS_DEVICE): StartedTransaction =
        flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"), mode)

    private fun postPresentation(started: StartedTransaction): ResultActions =
        mockMvc.perform(
            post("/openid4vp/response/{txId}", started.id.value)
                .contentType("application/x-www-form-urlencoded")
                .param("response", encryptedResponseFor(checkNotNull(flow.requestJwtFor(started.id)))),
        )

    private fun capturingControllerLog(action: () -> Unit): List<ILoggingEvent> {
        val logger = LoggerFactory.getLogger(OpenId4VpController::class.java) as Logger
        val appender = ListAppender<ILoggingEvent>().apply { start() }
        logger.addAppender(appender)
        try {
            action()
        } finally {
            logger.detachAppender(appender)
        }
        return appender.list
    }
}
