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

import dev.zilath.verifier.core.CredentialVerifier
import dev.zilath.verifier.core.OAuthStatusListChecker
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.StatusListFetcher
import dev.zilath.verifier.core.TrustEvaluator
import dev.zilath.verifier.openid4vp.ItWalletProfile
import dev.zilath.verifier.openid4vp.OpenId4VpVerificationFlow
import dev.zilath.verifier.openid4vp.RelyingPartyConfiguration
import dev.zilath.verifier.openid4vp.TransactionStore
import dev.zilath.verifier.openid4vp.TrustChainSource
import dev.zilath.verifier.openid4vp.TrustMarkSource
import dev.zilath.verifier.openid4vp.VerificationFlow
import dev.zilath.verifier.openid4vp.WalletProfile
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Condition
import org.springframework.context.annotation.ConditionContext
import org.springframework.context.annotation.Conditional
import org.springframework.core.type.AnnotatedTypeMetadata
import java.time.Clock

/**
 * Wires a [VerificationFlow] and its HTTP endpoints from `zilath.openid4vp.*` properties.
 * The integrating application MUST provide a [TrustEvaluator] bean, and either a
 * [StatusChecker] or a [StatusListFetcher], on which the starter builds an
 * [OAuthStatusListChecker]: deciding who to trust, and how to reach a status list, is never
 * a library default.
 *
 * It MAY declare a [TransactionStore] (a shared one, when it runs on more than one node), a
 * [WalletProfile], a [TrustChainSource] and a [TrustMarkSource] for an `openid_federation:`
 * relying party, a [CredentialVerifier] and a [Clock]: each is used where the starter would otherwise use
 * its own default, or nothing.
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
     * Token Status List revocation checking, once the application declares the one piece that
     * is its own: the [StatusListFetcher], which decides how a list is fetched — timeouts, size
     * cap, the network boundary its KDoc describes. Declare a [StatusChecker] to replace it.
     *
     * Declared before the relying party, which is conditional on a [StatusChecker] bean. The
     * starter used to build no checker at all, and the only examples in the repository
     * answered VALID to everything: a checker like that switches revocation off, since the
     * verifier asks it only about a credential that carries a status reference.
     */
    @Bean
    @ConditionalOnMissingBean(StatusChecker::class)
    @ConditionalOnBean(StatusListFetcher::class)
    fun statusChecker(
        fetcher: StatusListFetcher,
        clock: Clock,
    ): StatusChecker = OAuthStatusListChecker(fetcher, clock)

    /**
     * The relying party, assembled from `zilath.openid4vp.*`, under the application's
     * [WalletProfile] bean if it declares one and IT-Wallet's otherwise, and with the
     * application's [TrustChainSource] and [TrustMarkSource] beans, if any, supplying the
     * federation trust chain and trust marks.
     * Declare a [RelyingPartyConfiguration] bean of your own to replace it; the flow is then
     * built from yours.
     *
     * Deliberately conditional on three things at once: the `client-id` property, and
     * [TrustEvaluator] and [StatusChecker] beans — the checker the application's own or the
     * one built on its [StatusListFetcher]. If any is
     * missing the configuration is simply not created — and neither are the flow and the
     * controller, so no wallet-facing endpoint is ever exposed by an application that has
     * not said whom it trusts. A half-configured verifier that answers requests would be
     * worse than none.
     */
    @Bean
    @ConditionalOnMissingBean(RelyingPartyConfiguration::class, VerificationFlow::class)
    @ConditionalOnBean(TrustEvaluator::class, StatusChecker::class)
    @ConditionalOnProperty(prefix = "zilath.openid4vp", name = ["client-id"])
    @Suppress("LongParameterList") // Spring bean wiring: every parameter is an injected dependency
    fun relyingPartyConfiguration(
        properties: OpenId4VpProperties,
        trustEvaluator: TrustEvaluator,
        statusChecker: StatusChecker,
        profiles: ObjectProvider<WalletProfile>,
        trustChainSources: ObjectProvider<TrustChainSource>,
        trustMarkSources: ObjectProvider<TrustMarkSource>,
    ): RelyingPartyConfiguration =
        relyingPartyConfigurationOf(
            properties,
            trustEvaluator,
            statusChecker,
            profiles.getIfAvailable { ItWalletProfile },
            trustChainSources.getIfAvailable(),
            trustMarkSources.getIfAvailable(),
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

    /**
     * Publishes the entity configuration of the federation identity
     * `zilath.openid4vp.federation.*` describes, once there is one: a wallet resolving an
     * `openid_federation:` client id, and the federation onboarding the relying party, read
     * its metadata and keys there. Replace it as the controller above, with a bean of type
     * [OpenId4VpFederationController].
     *
     * Published when `zilath.openid4vp.federation.entity-id` is set, also for a
     * [RelyingPartyConfiguration] the application declares itself: one that carries a
     * federation identity gets the endpoint by setting that property as well, and with the
     * property set and no federation in the configuration, startup fails. It is not published
     * from the configuration alone because an application may already map this path itself.
     */
    @Bean
    @ConditionalOnBean(RelyingPartyConfiguration::class)
    @Conditional(OnFederationEntityId::class)
    @ConditionalOnMissingBean
    fun openId4VpFederationController(
        config: RelyingPartyConfiguration,
        clock: Clock,
    ): OpenId4VpFederationController = OpenId4VpFederationController(config, clock)
}

/**
 * Matches when `zilath.openid4vp.federation.entity-id` is set and not blank: blank means
 * absent, as it does for the starter's other optional properties, so that a placeholder
 * such as `${FEDERATION_ENTITY_ID:}` left unset configures no federation.
 */
internal class OnFederationEntityId : Condition {
    override fun matches(
        context: ConditionContext,
        metadata: AnnotatedTypeMetadata,
    ): Boolean = !context.environment.getProperty("zilath.openid4vp.federation.entity-id").isNullOrBlank()
}
