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

import dev.zilath.verifier.openid4vp.RelyingPartyConfiguration
import org.springframework.boot.context.properties.ConfigurationProperties

/**
 * Relying-party configuration of the OpenID4VP endpoints.
 * Keys are JWK JSON strings (EC P-256, private part included) and MUST come from
 * secured configuration (env, vault) — never from files committed to a repository.
 */
@ConfigurationProperties("zilath.openid4vp")
data class OpenId4VpProperties(
    val clientId: String = "",
    /** Public base URL of the request endpoint, e.g. `https://rp.example/openid4vp/request`. */
    val requestUriBase: String = "",
    /** Public base URL of the response endpoint, e.g. `https://rp.example/openid4vp/response`. */
    val responseUriBase: String = "",
    /** JWK JSON of the EC P-256 request signing key (with kid). */
    val requestSigningKeyJwk: String = "",
    /**
     * OPTIONAL, and best left empty: JWK JSON of a long-lived EC P-256 key (with kid) for
     * wallet responses.
     *
     * Without it every transaction encrypts to a key of its own, which the request object
     * publishes and the flow drops when the response arrives. Setting it is the opt-in to the
     * fallback [dev.zilath.verifier.openid4vp.RpKeys.responseEncryptionKey] describes: the key
     * is published in the federation entity configuration and a response encrypted to it is
     * accepted, for wallets that encrypt to the key resolved from the federation. Before the
     * fourth internal review this property was required, so that every application built on
     * the starter had the fallback on.
     */
    val responseEncryptionKeyJwk: String = "",
    val walletAuthorizationScheme: String = "openid4vp://",
    val transactionTimeToLiveSeconds: Long = DEFAULT_TTL_SECONDS,
    /** Same-device callback base, e.g. `https://rp.example/cb`; empty = cross-device only.
     *  Appended LAST to preserve positional-constructor compatibility for existing callers. */
    val sameDeviceCallbackBase: String = "",
    /**
     * The largest wallet response the flow decodes, in characters of the form body: a larger
     * one is refused as malformed before it is decrypted
     * ([RelyingPartyConfiguration.maxWalletResponseLength]). 1 MiB by default, room for an
     * issuer's trust chain in the credential header and a disclosed portrait.
     *
     * The servlet container limits the same body before the flow sees it, with a form limit
     * of its own, and a response it cuts never reaches the flow as a response: keep the
     * container's limit ABOVE this one, or holders are refused there. Tomcat, Spring Boot's
     * default, reads `server.tomcat.max-http-form-post-size`, 2 MiB unless set; Jetty reads
     * `server.jetty.max-http-form-post-size`, 200 000 bytes unless set — below this default,
     * so on Jetty raise it, or lower this.
     */
    val maxWalletResponseLength: Int = RelyingPartyConfiguration.DEFAULT_MAX_WALLET_RESPONSE_LENGTH,
) {
    /** The JWK properties carry private key material: never let them reach a log. */
    override fun toString(): String =
        "OpenId4VpProperties(clientId=$clientId, requestUriBase=$requestUriBase, " +
            "responseUriBase=$responseUriBase, requestSigningKeyJwk=[REDACTED], " +
            "responseEncryptionKeyJwk=[REDACTED], walletAuthorizationScheme=$walletAuthorizationScheme, " +
            "transactionTimeToLiveSeconds=$transactionTimeToLiveSeconds, " +
            "sameDeviceCallbackBase=$sameDeviceCallbackBase, maxWalletResponseLength=$maxWalletResponseLength)"

    companion object {
        const val DEFAULT_TTL_SECONDS = 300L
    }
}
