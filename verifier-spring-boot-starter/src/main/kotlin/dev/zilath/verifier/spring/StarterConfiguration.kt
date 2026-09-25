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
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TrustEvaluator
import dev.zilath.verifier.openid4vp.OPENID_FEDERATION_PREFIX
import dev.zilath.verifier.openid4vp.RelyingPartyConfiguration
import dev.zilath.verifier.openid4vp.RpEndpoints
import dev.zilath.verifier.openid4vp.RpFederationConfig
import dev.zilath.verifier.openid4vp.RpKeys
import dev.zilath.verifier.openid4vp.TrustChainSource
import dev.zilath.verifier.openid4vp.WalletProfile
import java.time.Duration

/*
 * From `zilath.openid4vp.*` to the library's configuration. The library checks every value;
 * what is here says, in the property names an operator writes, what is missing.
 */

/**
 * The relying party [properties] describe, trusting through [trustEvaluator] and
 * [statusChecker], under [profile], with request objects carrying the chain of
 * [trustChainSource] when the application declares one.
 */
internal fun relyingPartyConfigurationOf(
    properties: OpenId4VpProperties,
    trustEvaluator: TrustEvaluator,
    statusChecker: StatusChecker,
    profile: WalletProfile,
    trustChainSource: TrustChainSource?,
): RelyingPartyConfiguration {
    // The library refuses this too, in its own terms: the fourth internal review found an
    // operator of the starter told that "a federation configuration" was required, with no
    // property that could provide one.
    require(!properties.clientId.startsWith(OPENID_FEDERATION_PREFIX) || properties.federation.entityId.isNotBlank()) {
        "zilath.openid4vp.client-id uses the openid_federation: prefix, which needs zilath.openid4vp.federation.* " +
            "(entity-id, federation-key-jwk, authority-hints, organization-name, contacts)"
    }
    return RelyingPartyConfiguration(
        clientId = properties.clientId,
        endpoints =
            RpEndpoints(
                properties.requestUriBase,
                properties.responseUriBase,
                properties.sameDeviceCallbackBase.ifBlank { null },
                // The starter's controller serves the request object by POST as well.
                requestUriMethodPost = true,
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
        profile = profile,
        federation = federationOf(properties.federation, trustChainSource),
        maxWalletResponseLength = properties.maxWalletResponseLength,
    )
}

/**
 * The federation identity `zilath.openid4vp.federation.*` describes, or null when it names
 * no entity id — and then nothing else of it may be set: a federation half written down is
 * a mistake to report, not to ignore.
 */
private fun federationOf(
    federation: OpenId4VpProperties.Federation,
    trustChainSource: TrustChainSource?,
): RpFederationConfig? {
    if (federation.entityId.isBlank()) {
        require(federation == OpenId4VpProperties.Federation()) {
            "zilath.openid4vp.federation.* is set without zilath.openid4vp.federation.entity-id"
        }
        require(trustChainSource == null) {
            "a TrustChainSource bean is declared without zilath.openid4vp.federation.entity-id"
        }
        return null
    }
    require(federation.federationKeyJwk.isNotBlank()) {
        "zilath.openid4vp.federation.federation-key-jwk is required with a federation entity-id"
    }
    require(federation.organizationName.isNotBlank()) {
        "zilath.openid4vp.federation.organization-name is required with a federation entity-id: wallets show it"
    }
    val federationKey = ECKey.parse(federation.federationKeyJwk)
    return try {
        RpFederationConfig(
            entityId = federation.entityId,
            federationKey = federationKey,
            authorityHints = federation.authorityHints,
            organizationName = federation.organizationName,
            contacts = federation.contacts,
            trustChain = federation.trustChain,
            trustChainSource = trustChainSource,
        )
    } catch (invalid: IllegalArgumentException) {
        // The library's message says what is wrong; here it gains the properties it is about.
        throw IllegalArgumentException("zilath.openid4vp.federation: ${invalid.message}", invalid)
    }
}
