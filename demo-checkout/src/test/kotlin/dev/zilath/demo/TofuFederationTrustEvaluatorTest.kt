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
package dev.zilath.demo

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import dev.zilath.demo.cedsim.CedSim
import dev.zilath.verifier.core.IssuerTrustInput
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.trust.FederationFetcher
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Date

/**
 * The conformance run's shape: the tool's anchor is reached on localhost but names itself
 * with an entity id nothing can fetch — the demo's insecure-TLS fetcher refuses every
 * non-loopback host — and its mock PID carries the whole chain in the header. The online
 * refresh can never succeed there, so the wrapper must let the header decide.
 */
class TofuFederationTrustEvaluatorTest {
    private val clock = Clock.fixed(Instant.parse("2026-08-25T10:00:00Z"), ZoneOffset.UTC)
    private val keys = CedSim.generateKeys()
    private val servedAt = "https://localhost:3001"

    /** The anchor's configuration, served on localhost, naming the anchor's real entity id. */
    private val anchorConfiguration: String =
        SignedJWT(
            JWSHeader
                .Builder(JWSAlgorithm.ES256)
                .keyID(keys.anchor.keyID)
                .type(JOSEObjectType("entity-statement+jwt"))
                .build(),
            JWTClaimsSet
                .Builder()
                .issuer(CedSim.ANCHOR_ID)
                .subject(CedSim.ANCHOR_ID)
                .issueTime(Date.from(clock.instant()))
                .expirationTime(Date.from(clock.instant().plusSeconds(3600)))
                .claim("jwks", mapOf("keys" to listOf(keys.anchor.toPublicJWK().toJSONObject())))
                .build(),
        ).apply { sign(ECDSASigner(keys.anchor)) }.serialize()

    /** Only loopback is reachable, as with the demo's insecure-TLS fetcher. */
    private val loopbackOnly =
        FederationFetcher { url ->
            check(url == "$servedAt/.well-known/openid-federation") { "refused outside loopback" }
            anchorConfiguration
        }

    @Test
    fun `a conformance-style chain carried in the header is trusted`() {
        val decision =
            TofuFederationTrustEvaluator(servedAt, loopbackOnly, clock).evaluate(
                IssuerTrustInput(
                    issuer = CedSim.ISSUER_ID,
                    keyId = null,
                    certificateChain = emptyList(),
                    trustChain = CedSim.buildTrustChain(keys, clock),
                ),
            )
        assertThat(decision).isInstanceOf(TrustDecision.Trusted::class.java)
    }
}
