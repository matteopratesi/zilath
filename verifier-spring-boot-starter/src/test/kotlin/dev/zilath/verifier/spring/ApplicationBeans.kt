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

import com.nimbusds.jose.jwk.ECKey
import dev.zilath.verifier.core.CredentialStatus
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.TrustEvaluator
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.runner.AbstractApplicationContextRunner
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import org.springframework.boot.test.context.runner.WebApplicationContextRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/** What every application must declare before the starter builds anything, and a verifier the test scripts. */
@Configuration(proxyBeanMethods = false)
class ApplicationBeans {
    @Bean
    fun trustEvaluator(): TrustEvaluator = TrustEvaluator { TrustDecision.Untrusted("configuration test") }

    @Bean
    fun statusChecker(): StatusChecker = StatusChecker { _, _ -> CredentialStatus.UNKNOWN }

    @Bean
    fun scriptedVerifier(): ScriptedVerifier = ScriptedVerifier()
}

/** The starter alone, with the application's beans and the properties of a plain `https` relying party. */
internal fun starterRunner(signingKey: ECKey): ApplicationContextRunner =
    ApplicationContextRunner().withStarter(signingKey)

/** The same, as a web application, for MockMvc. */
internal fun webStarterRunner(signingKey: ECKey): WebApplicationContextRunner =
    WebApplicationContextRunner().withStarter(signingKey)

private fun <R : AbstractApplicationContextRunner<R, *, *>> R.withStarter(signingKey: ECKey): R =
    withConfiguration(AutoConfigurations.of(OpenId4VpAutoConfiguration::class.java))
        .withUserConfiguration(ApplicationBeans::class.java)
        .withPropertyValues(
            "zilath.openid4vp.client-id=https://rp.example",
            "zilath.openid4vp.request-uri-base=https://rp.example/openid4vp/request",
            "zilath.openid4vp.response-uri-base=https://rp.example/openid4vp/response",
            "zilath.openid4vp.request-signing-key-jwk=${signingKey.toJSONString()}",
        )
