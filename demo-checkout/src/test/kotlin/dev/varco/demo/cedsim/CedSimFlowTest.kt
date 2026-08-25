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
package dev.varco.demo.cedsim

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.SignedJWT
import dev.varco.verifier.core.CredentialStatus
import dev.varco.verifier.core.RejectionReason
import dev.varco.verifier.core.SdJwtVcCredentialVerifier
import dev.varco.verifier.core.StatusChecker
import dev.varco.verifier.openid4vp.DirectPostBody
import dev.varco.verifier.openid4vp.FlowOutcome
import dev.varco.verifier.openid4vp.OpenId4VpVerificationFlow
import dev.varco.verifier.openid4vp.PresentationRequest
import dev.varco.verifier.openid4vp.RelyingPartyConfiguration
import dev.varco.verifier.openid4vp.RpEndpoints
import dev.varco.verifier.openid4vp.RpKeys
import dev.varco.verifier.trust.FederationFetcher
import dev.varco.verifier.trust.FederationTrustEvaluator
import dev.varco.verifier.trust.TrustAnchorConfig
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonPrimitive
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class CedSimFlowTest {
    private val clock = Clock.fixed(Instant.parse("2026-08-25T10:00:00Z"), ZoneOffset.UTC)
    private val keys = CedSim.generateKeys()
    private val config =
        RelyingPartyConfiguration(
            clientId = "https://demo.varco.example",
            endpoints = RpEndpoints("https://demo.varco.example/req", "https://demo.varco.example/res"),
            keys =
                RpKeys(
                    requestSigningKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate(),
                    responseEncryptionKey = ECKeyGenerator(Curve.P_256).keyID("rp-enc").generate(),
                ),
            trustEvaluator =
                FederationTrustEvaluator(
                    TrustAnchorConfig(CedSim.ANCHOR_ID, listOf(keys.anchor.toPublicJWK())),
                    FederationFetcher { error("offline: the simulated chain travels in the header") },
                    clock,
                ),
            statusChecker = StatusChecker { CredentialStatus.VALID },
        )
    private val flow = OpenId4VpVerificationFlow.withInMemoryStore(config, SdJwtVcCredentialVerifier(), clock)

    private fun encryptionKeyOf(clientMetadata: Map<String, Any?>): JWK {
        val jwks = clientMetadata["jwks"] as Map<*, *>
        val list = jwks["keys"] as List<*>

        @Suppress("UNCHECKED_CAST")
        return JWK.parse(JSONObjectUtils.toJSONString(list.first() as Map<String, Any?>))
    }

    private fun presentSimulatedCed(withKeys: CedSim.Keys): FlowOutcome {
        val request = PresentationRequest.forVct(CedSim.VCT, CedSim.CLAIM_PATHS, CedSim.CREDENTIAL_QUERY_ID)
        val started = flow.start(request)
        val jar = SignedJWT.parse(checkNotNull(flow.requestJwtFor(started.id)))
        val claims = jar.jwtClaimsSet
        val presentation =
            CedSim.mintPresentation(withKeys, claims.getStringClaim("nonce"), claims.getStringClaim("client_id"), clock)
        val response =
            CedSim.buildEncryptedResponse(
                claims.getStringClaim("state"),
                presentation,
                encryptionKeyOf(claims.getJSONObjectClaim("client_metadata")),
            )
        return flow.handleWalletResponse(started.id, DirectPostBody(mapOf("response" to response)))
    }

    @Test
    fun `the simulated CED unlocks the companion entitlement end to end`() {
        val outcome = presentSimulatedCed(keys)
        assertThat(outcome).isInstanceOf(FlowOutcome.Verified::class.java)
        val claims = (outcome as FlowOutcome.Verified).claims.claims
        assertThat(claims["companion_entitlement"]?.jsonPrimitive?.boolean).isTrue()
        assertThat(claims["given_name"]?.jsonPrimitive?.content).isEqualTo("Maria")
        // The simulation models only card-level facts: never conditions or subcategories.
        assertThat(claims.keys).doesNotContain("diagnosis", "art3c3", "percentage")
    }

    @Test
    fun `a simulated CED from an unknown federation is rejected`() {
        val impostorKeys = CedSim.generateKeys()
        val outcome = presentSimulatedCed(impostorKeys)
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.UNTRUSTED_ISSUER)
    }

    @Test
    fun `keys survive a write-read roundtrip`(
        @TempDir dir: Path,
    ) {
        CedSim.writeKeys(dir, keys)
        val reloaded = CedSim.readKeys(dir)
        assertThat(reloaded.anchor.toJSONString()).isEqualTo(keys.anchor.toJSONString())
        assertThat(reloaded.issuerCredential.keyID).isEqualTo(keys.issuerCredential.keyID)
        assertThat(dir.resolve("anchor-jwks.json")).exists()
    }
}
