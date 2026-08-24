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

import org.springframework.boot.context.properties.ConfigurationProperties

/**
 * Relying-party configuration of the OpenID4VP endpoints.
 * Keys are JWK JSON strings (EC P-256, private part included) and MUST come from
 * secured configuration (env, vault) — never from files committed to a repository.
 */
@ConfigurationProperties("varco.openid4vp")
data class OpenId4VpProperties(
    val clientId: String = "",
    /** Public base URL of the request endpoint, e.g. `https://rp.example/openid4vp/request`. */
    val requestUriBase: String = "",
    /** Public base URL of the response endpoint, e.g. `https://rp.example/openid4vp/response`. */
    val responseUriBase: String = "",
    /** JWK JSON of the EC P-256 request signing key (with kid). */
    val requestSigningKeyJwk: String = "",
    /** JWK JSON of the EC P-256 response encryption key (with kid). */
    val responseEncryptionKeyJwk: String = "",
    val walletAuthorizationScheme: String = "openid4vp://",
    val transactionTimeToLiveSeconds: Long = DEFAULT_TTL_SECONDS,
) {
    /** The JWK properties carry private key material: never let them reach a log. */
    override fun toString(): String =
        "OpenId4VpProperties(clientId=$clientId, requestUriBase=$requestUriBase, " +
            "responseUriBase=$responseUriBase, requestSigningKeyJwk=[REDACTED], " +
            "responseEncryptionKeyJwk=[REDACTED], walletAuthorizationScheme=$walletAuthorizationScheme, " +
            "transactionTimeToLiveSeconds=$transactionTimeToLiveSeconds)"

    companion object {
        const val DEFAULT_TTL_SECONDS = 300L
    }
}
