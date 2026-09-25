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
import dev.zilath.verifier.core.CredentialVerifier
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TrustEvaluator
import dev.zilath.verifier.openid4vp.OpenId4VpVerificationFlow
import dev.zilath.verifier.openid4vp.RelyingPartyConfiguration
import dev.zilath.verifier.openid4vp.RpEndpoints
import dev.zilath.verifier.openid4vp.RpKeys
import dev.zilath.verifier.openid4vp.TransactionStore
import dev.zilath.verifier.openid4vp.VerificationFlow
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import java.time.Clock
import java.time.Duration

/**
 * Wires a [VerificationFlow] and its HTTP endpoints from `zilath.openid4vp.*` properties.
 * The integrating application MUST provide [TrustEvaluator] and [StatusChecker] beans:
 * deciding who to trust is never a library default.
 */
@AutoConfiguration
@EnableConfigurationProperties(OpenId4VpProperties::class)
class OpenId4VpAutoConfiguration {
    /** The SD-JWT VC verifier. Declare your own [CredentialVerifier] bean to replace it. */
    @Bean
    @ConditionalOnMissingBean
    fun credentialVerifier(): CredentialVerifier = SdJwtVcCredentialVerifier()

    /**
     * The clock every expiry and key-binding freshness check reads. UTC by default;
     * override with your own [Clock] bean — a fixed one is how tests move time.
     */
    @Bean
    @ConditionalOnMissingBean
    fun verificationClock(): Clock = Clock.systemUTC()

    /**
     * The relying party, assembled from `zilath.openid4vp.*`. Declare a
     * [RelyingPartyConfiguration] bean of your own to replace it; the flow is then built
     * from yours.
     *
     * Deliberately conditional on three things at once: the `client-id` property, and
     * [TrustEvaluator] and [StatusChecker] beans the application must supply. If any is
     * missing the configuration is simply not created — and neither are the flow and the
     * controller, so no wallet-facing endpoint is ever exposed by an application that has
     * not said whom it trusts. A half-configured verifier that answers requests would be
     * worse than none.
     */
    @Bean
    @ConditionalOnMissingBean(RelyingPartyConfiguration::class, VerificationFlow::class)
    @ConditionalOnBean(TrustEvaluator::class, StatusChecker::class)
    @ConditionalOnProperty(prefix = "zilath.openid4vp", name = ["client-id"])
    fun relyingPartyConfiguration(
        properties: OpenId4VpProperties,
        trustEvaluator: TrustEvaluator,
        statusChecker: StatusChecker,
    ): RelyingPartyConfiguration =
        RelyingPartyConfiguration(
            clientId = properties.clientId,
            endpoints =
                RpEndpoints(
                    properties.requestUriBase,
                    properties.responseUriBase,
                    properties.sameDeviceCallbackBase.ifBlank { null },
                ),
            keys =
                RpKeys(
                    requestSigningKey = ECKey.parse(properties.requestSigningKeyJwk),
                    responseEncryptionKey = properties.responseEncryptionKeyJwk.ifBlank { null }?.let(ECKey::parse),
                ),
            trustEvaluator = trustEvaluator,
            statusChecker = statusChecker,
            walletAuthorizationScheme = properties.walletAuthorizationScheme,
            transactionTimeToLive = Duration.ofSeconds(properties.transactionTimeToLiveSeconds),
            maxWalletResponseLength = properties.maxWalletResponseLength,
        )

    /**
     * The relying-party flow, on the application's [TransactionStore] bean when it declares
     * one — a deployment with more than one node needs a shared store, and SECURITY.md says
     * to bring one — and on the in-memory store otherwise. Before the fourth internal review
     * a store bean was ignored: the starter always wired the in-memory store, and the only
     * way around it was rebuilding the whole flow by hand.
     *
     * Closed with the application context, as an [AutoCloseable] bean is. That stops and
     * empties the in-memory store the flow created; a store of the application's is its
     * own bean, closed by the context if it is closeable, never by the flow.
     */
    @Bean
    @ConditionalOnMissingBean(VerificationFlow::class)
    @ConditionalOnBean(RelyingPartyConfiguration::class)
    fun verificationFlow(
        config: RelyingPartyConfiguration,
        verifier: CredentialVerifier,
        clock: Clock,
        stores: ObjectProvider<TransactionStore>,
    ): OpenId4VpVerificationFlow =
        stores.getIfAvailable()?.let { OpenId4VpVerificationFlow(config, verifier, it, clock) }
            ?: OpenId4VpVerificationFlow.withInMemoryStore(config, verifier, clock)

    /**
     * Publishes the wallet-facing endpoints, but only once a [VerificationFlow] exists.
     *
     * To take the routes over you must declare a bean OF TYPE [OpenId4VpController]:
     * `@ConditionalOnMissingBean` matches on that type, so a controller of your own class
     * does not suppress this one and both would map the same paths.
     */
    @Bean
    @ConditionalOnBean(VerificationFlow::class)
    @ConditionalOnMissingBean
    fun openId4VpController(flow: VerificationFlow): OpenId4VpController = OpenId4VpController(flow)
}
