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

import com.nimbusds.jose.jwk.ECKey
import dev.varco.verifier.core.CredentialVerifier
import dev.varco.verifier.core.SdJwtVcCredentialVerifier
import dev.varco.verifier.core.StatusChecker
import dev.varco.verifier.core.TrustEvaluator
import dev.varco.verifier.openid4vp.OpenId4VpVerificationFlow
import dev.varco.verifier.openid4vp.RelyingPartyConfiguration
import dev.varco.verifier.openid4vp.RpEndpoints
import dev.varco.verifier.openid4vp.RpKeys
import dev.varco.verifier.openid4vp.VerificationFlow
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import java.time.Clock
import java.time.Duration

/**
 * Wires a [VerificationFlow] and its HTTP endpoints from `varco.openid4vp.*` properties.
 * The integrating application MUST provide [TrustEvaluator] and [StatusChecker] beans:
 * deciding who to trust is never a library default.
 */
@AutoConfiguration
@EnableConfigurationProperties(OpenId4VpProperties::class)
class OpenId4VpAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean
    fun credentialVerifier(): CredentialVerifier = SdJwtVcCredentialVerifier()

    @Bean
    @ConditionalOnMissingBean
    fun verificationClock(): Clock = Clock.systemUTC()

    @Bean
    @ConditionalOnMissingBean(VerificationFlow::class)
    @ConditionalOnBean(TrustEvaluator::class, StatusChecker::class)
    @ConditionalOnProperty(prefix = "varco.openid4vp", name = ["client-id"])
    fun verificationFlow(
        properties: OpenId4VpProperties,
        verifier: CredentialVerifier,
        trustEvaluator: TrustEvaluator,
        statusChecker: StatusChecker,
        clock: Clock,
    ): VerificationFlow {
        val config =
            RelyingPartyConfiguration(
                clientId = properties.clientId,
                endpoints = RpEndpoints(properties.requestUriBase, properties.responseUriBase),
                keys =
                    RpKeys(
                        requestSigningKey = ECKey.parse(properties.requestSigningKeyJwk),
                        responseEncryptionKey = ECKey.parse(properties.responseEncryptionKeyJwk),
                    ),
                trustEvaluator = trustEvaluator,
                statusChecker = statusChecker,
                walletAuthorizationScheme = properties.walletAuthorizationScheme,
                transactionTimeToLive = Duration.ofSeconds(properties.transactionTimeToLiveSeconds),
            )
        return OpenId4VpVerificationFlow.withInMemoryStore(config, verifier, clock)
    }

    @Bean
    @ConditionalOnBean(VerificationFlow::class)
    @ConditionalOnMissingBean
    fun openId4VpController(flow: VerificationFlow): OpenId4VpController = OpenId4VpController(flow)
}
