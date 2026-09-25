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
package dev.zilath.verifier.core

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.SignedJWT
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

/**
 * The production IT-Wallet federation documents frozen on 2026-09-24: trust anchor,
 * its statement about the European Disability Card issuer, and that issuer's entity
 * configuration. Provenance, sizes and validity windows are in the README next to them.
 */
object IpzsFederationSnapshot {
    const val TRUST_ANCHOR = "https://ta.wallet.ipzs.it"
    const val CED_ISSUER = "https://eaa.wallet.ipzs.it/1-0"

    /** The kid of the issuer's credential signing key, in `openid_credential_issuer.jwks`. */
    const val CED_ISSUER_SIGNING_KID = "dcb47a053c6c725838f6a5ea8855558f90ee3cf97eeb8a94fe7e6a0e364d3b27"

    /** The European Disability Card type the issuer lists in `credential_configurations_supported`. */
    const val CED_VCT = "https://ta.wallet.ipzs.it/vct/v1.0.0/europeandisabilitycard"

    /** Inside the validity window of all three documents; tests must use it, never a live clock. */
    val INSIDE_EVERY_WINDOW: Instant = Instant.ofEpochSecond(1_790_290_000)

    val clock: Clock get() = Clock.fixed(INSIDE_EVERY_WINDOW, ZoneOffset.UTC)

    val trustAnchorEntityConfiguration: String get() = read("ta-entity-configuration.jwt")
    val statementAboutCedIssuer: String get() = read("ta-statement-about-eaa-1-0.jwt")
    val cedIssuerEntityConfiguration: String get() = read("eaa-1-0-entity-configuration.jwt")

    /** The chain as an issuer would embed it in `trust_chain`: leaf first, anchor's statement last. */
    val cedIssuerChain: List<String> get() = listOf(cedIssuerEntityConfiguration, statementAboutCedIssuer)

    /** The anchor's federation keys, taken from its own entity configuration as an integrator would. */
    val trustAnchorKeys: JWKSet
        get() = JWKSet.parse(SignedJWT.parse(trustAnchorEntityConfiguration).jwtClaimsSet.getJSONObjectClaim("jwks"))

    /** What the three documents answer to, for a recording fetcher: URL to body. */
    val servedDocuments: Map<String, String>
        get() =
            mapOf(
                "$TRUST_ANCHOR/.well-known/openid-federation" to trustAnchorEntityConfiguration,
                "$CED_ISSUER/.well-known/openid-federation" to cedIssuerEntityConfiguration,
                "$TRUST_ANCHOR/federation_fetch_endpoint?sub=https%3A%2F%2Feaa.wallet.ipzs.it%2F1-0" to
                    statementAboutCedIssuer,
            )

    private fun read(name: String): String =
        checkNotNull(javaClass.getResourceAsStream("/dev/zilath/verifier/ipzs-2026-09-24/$name")) {
            "missing frozen IPZS document $name"
        }.use { it.readBytes().toString(Charsets.US_ASCII).trim() }
}
