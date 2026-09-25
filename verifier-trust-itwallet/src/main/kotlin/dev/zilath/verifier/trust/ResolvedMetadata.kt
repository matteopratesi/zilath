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
package dev.zilath.verifier.trust

import com.nimbusds.jose.jwk.JWK

/*
 * What the leaf's RESOLVED `openid_credential_issuer` metadata grants — after the immediate
 * superior's metadata, the constraints and every superior's policy — and nothing else.
 */

/**
 * The keys the leaf signs credentials with: its resolved `jwks`, or the chain fails.
 *
 * No fallback. Falling back to the leaf's federation keys turned a metadata_policy that
 * RESTRICTS openid_credential_issuer.jwks into one that widens: policy removes the key set,
 * the fallback hands over a different, unconstrained one. A leaf that published no
 * openid_credential_issuer at all got the same gift. Federation keys sign entity
 * statements; credential keys sign credentials. The separation is the point.
 */
internal fun credentialKeysOf(issuerMetadata: Map<*, *>?): List<JWK> =
    jwksOf(issuerMetadata?.get("jwks") as? Map<*, *>).ifEmpty {
        trustFail("the resolved metadata advertises no credential signing keys")
    }

/**
 * The credential types the leaf may issue: the `vct` of every SD-JWT entry (`dc+sd-jwt`,
 * or the earlier `vc+sd-jwt`) in its RESOLVED `credential_configurations_supported` —
 * after the immediate superior's metadata and every superior's policy, so a superior that
 * restricts the section restricts the types.
 *
 * IT-Wallet 1.4.6 §6.12.1 requires a relying party to check "that the Credential Issuer
 * is allowed in the issuance of the Credential of their interest". Before the fourth
 * internal review nothing did: any member of the federation, in any role, that published
 * credential signing keys could issue any type — a relying party a disability card. The
 * section is REQUIRED in credential issuer metadata by OpenID4VCI 1.0, and essential in
 * the production anchor's policy; a leaf that lacks it, or lists no SD-JWT entry, gets an
 * empty set, which authorises nothing.
 *
 * What this cannot stop is a member that holds its own federation key declaring a type in
 * its own configuration: only a superior's metadata or policy on the section, or trust
 * marks — which this library does not check — bind the role from above.
 */
internal fun credentialTypesOf(issuerMetadata: Map<*, *>?): Set<String> {
    val configurations = issuerMetadata?.get("credential_configurations_supported") as? Map<*, *> ?: return emptySet()
    return configurations.values
        .mapNotNull { entry -> (entry as? Map<*, *>)?.takeIf { it["format"] in SD_JWT_FORMATS }?.get("vct") as? String }
        .toSet()
}

private val SD_JWT_FORMATS = setOf("dc+sd-jwt", "vc+sd-jwt")
