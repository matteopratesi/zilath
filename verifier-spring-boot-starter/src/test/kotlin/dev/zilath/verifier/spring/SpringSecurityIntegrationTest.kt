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
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.TrustEvaluator
import dev.zilath.verifier.openid4vp.PresentationRequest
import dev.zilath.verifier.openid4vp.VerificationFlow
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

/**
 * The wallet's endpoints in an application that uses Spring Security, with the chain the
 * README gives. The wallet holds no session and no CSRF token: with Spring Security's
 * defaults every holder was refused, and the tempting fix — CSRF off, or everything permitted —
 * weakens the whole application.
 */
@SpringBootTest(classes = [SpringSecurityIntegrationTest.SecuredApp::class])
@AutoConfigureMockMvc
class SpringSecurityIntegrationTest {
    // Auto-configuration only, no component scan: see StarterSmokeTest.
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @Import(ApplicationSecurity::class, WalletEndpointsSecurity::class)
    class SecuredApp : RequiredBeans()

    /** The chain in the README, word for word. */
    @Configuration(proxyBeanMethods = false)
    class WalletEndpointsSecurity {
        @Bean
        @Order(1)
        fun walletEndpoints(http: HttpSecurity): SecurityFilterChain =
            http
                .securityMatcher("/openid4vp/request/**", "/openid4vp/response/**", "/.well-known/openid-federation")
                .authorizeHttpRequests { it.anyRequest().permitAll() }
                .csrf { it.ignoringRequestMatchers("/openid4vp/request/**", "/openid4vp/response/**") }
                .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
                .build()
    }

    companion object {
        @JvmStatic
        @DynamicPropertySource
        fun rpProperties(registry: DynamicPropertyRegistry) = registerRelyingParty(registry)
    }

    @Autowired
    lateinit var mockMvc: MockMvc

    @Autowired
    lateinit var flow: VerificationFlow

    @Test
    fun `with the documented chain the wallet reaches its endpoints and nothing else opens`() {
        val txId = start(flow)
        mockMvc
            .perform(get("/openid4vp/request/{txId}", txId))
            .andExpect(status().isOk)
            .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")))
        mockMvc
            .perform(
                post("/openid4vp/request/{txId}", txId)
                    .contentType("application/x-www-form-urlencoded")
                    .param("wallet_nonce", "wallet-nonce-1"),
            ).andExpect(status().isOk)
        postWalletError(mockMvc, txId).andExpect(status().isOk)
        // The application's own pages stay behind its chain.
        mockMvc.perform(get("/anything-else")).andExpect(status().isUnauthorized)
    }
}

/** The same application without the README's chain: Spring Security's defaults alone. */
@SpringBootTest(classes = [SpringSecurityDefaultsTest.DefaultsApp::class])
@AutoConfigureMockMvc
class SpringSecurityDefaultsTest {
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @Import(ApplicationSecurity::class)
    class DefaultsApp : RequiredBeans()

    companion object {
        @JvmStatic
        @DynamicPropertySource
        fun rpProperties(registry: DynamicPropertyRegistry) = registerRelyingParty(registry)
    }

    @Autowired
    lateinit var mockMvc: MockMvc

    @Autowired
    lateinit var flow: VerificationFlow

    @Test
    fun `with Spring Security's defaults alone the wallet is refused`() {
        val txId = start(flow)
        mockMvc.perform(get("/openid4vp/request/{txId}", txId)).andExpect(status().isUnauthorized)
        postWalletError(mockMvc, txId).andExpect(status().is4xxClientError)
    }
}

/** What every application declares before the starter builds anything. */
abstract class RequiredBeans {
    @Bean
    fun trustEvaluator(): TrustEvaluator = TrustEvaluator { TrustDecision.Untrusted("security test") }

    @Bean
    fun statusChecker(): StatusChecker = StatusChecker { _, _ -> CredentialStatus.UNKNOWN }
}

/** The application's own chain, as Spring Security's defaults have it: everything authenticated. */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
class ApplicationSecurity {
    @Bean
    fun application(http: HttpSecurity): SecurityFilterChain =
        http
            .authorizeHttpRequests { it.anyRequest().authenticated() }
            .httpBasic(Customizer.withDefaults())
            .build()
}

private val securityTestSigningKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate()

private fun registerRelyingParty(registry: DynamicPropertyRegistry) {
    registry.add("zilath.openid4vp.client-id") { "https://rp.example" }
    registry.add("zilath.openid4vp.request-uri-base") { "https://rp.example/openid4vp/request" }
    registry.add("zilath.openid4vp.response-uri-base") { "https://rp.example/openid4vp/response" }
    registry.add("zilath.openid4vp.request-signing-key-jwk") { securityTestSigningKey.toJSONString() }
}

private fun start(flow: VerificationFlow): String =
    flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement")).id.value

private fun postWalletError(
    mockMvc: MockMvc,
    txId: String,
): ResultActions =
    mockMvc.perform(
        post("/openid4vp/response/{txId}", txId)
            .contentType("application/x-www-form-urlencoded")
            .param("error", "access_denied"),
    )
