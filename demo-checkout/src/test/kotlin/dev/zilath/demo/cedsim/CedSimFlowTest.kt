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
package dev.zilath.demo.cedsim

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.SignedJWT
import dev.zilath.demo.ConformanceController
import dev.zilath.verifier.core.CredentialStatus
import dev.zilath.verifier.core.RejectionReason
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.openid4vp.DirectPostBody
import dev.zilath.verifier.openid4vp.FlowMode
import dev.zilath.verifier.openid4vp.FlowOutcome
import dev.zilath.verifier.openid4vp.OpenId4VpVerificationFlow
import dev.zilath.verifier.openid4vp.PresentationRequest
import dev.zilath.verifier.openid4vp.RelyingPartyConfiguration
import dev.zilath.verifier.openid4vp.RpEndpoints
import dev.zilath.verifier.openid4vp.RpKeys
import dev.zilath.verifier.trust.FederationFetcher
import dev.zilath.verifier.trust.FederationTrustEvaluator
import dev.zilath.verifier.trust.TrustAnchorConfig
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
            clientId = "https://demo.zilath.example",
            endpoints =
                RpEndpoints(
                    "https://demo.zilath.example/req",
                    "https://demo.zilath.example/res",
                    sameDeviceCallbackBase = "https://demo.zilath.example/cb",
                ),
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
            statusChecker = StatusChecker { _, _ -> CredentialStatus.VALID },
        )
    private val flow = OpenId4VpVerificationFlow.withInMemoryStore(config, SdJwtVcCredentialVerifier(), clock)
    private var lastStartedId: dev.zilath.verifier.openid4vp.TransactionId? = null

    private fun encryptionKeyOf(clientMetadata: Map<String, Any?>): JWK {
        val jwks = clientMetadata["jwks"] as Map<*, *>
        val list = jwks["keys"] as List<*>

        @Suppress("UNCHECKED_CAST")
        return JWK.parse(JSONObjectUtils.toJSONString(list.first() as Map<String, Any?>))
    }

    private fun presentSimulatedCed(
        withKeys: CedSim.Keys,
        constantAttendanceAllowance: Boolean = true,
        expiryDate: String = "2030-12-31",
        mode: FlowMode = FlowMode.CROSS_DEVICE,
    ): FlowOutcome {
        val request = PresentationRequest.forVct(CedSim.VCT, CedSim.CLAIM_PATHS, CedSim.CREDENTIAL_QUERY_ID)
        val started = flow.start(request, mode)
        lastStartedId = started.id
        val jar = SignedJWT.parse(checkNotNull(flow.requestJwtFor(started.id)))
        val claims = jar.jwtClaimsSet
        val presentation =
            CedSim.mintPresentation(
                withKeys,
                claims.getStringClaim("nonce"),
                claims.getStringClaim("client_id"),
                clock,
                constantAttendanceAllowance,
                expiryDate,
            )
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
        assertThat(claims["constant_attendance_allowance"]?.jsonPrimitive?.boolean).isTrue()
        assertThat(claims["given_name"]?.jsonPrimitive?.content).isEqualTo("Maria")
        // The simulation discloses only the minimized subset: never the portrait or the
        // document number, and never conditions or subcategories.
        assertThat(claims.keys).doesNotContain("diagnosis", "art3c3", "percentage", "portrait", "document_number")
    }

    @Test
    fun `a valid card WITHOUT the entitlement verifies but does not grant the ticket`() {
        val outcome = presentSimulatedCed(keys, constantAttendanceAllowance = false)
        // The credential itself is cryptographically fine...
        assertThat(outcome).isInstanceOf(FlowOutcome.Verified::class.java)
        // ...but the checkout policy must refuse the benefit.
        val claims = (outcome as FlowOutcome.Verified).claims.claims
        assertThat(CedSim.entitlementGranted(claims, clock)).isFalse()
    }

    @Test
    fun `an expired card does not grant the ticket`() {
        val outcome = presentSimulatedCed(keys, expiryDate = "2026-08-24")
        val claims = (outcome as FlowOutcome.Verified).claims.claims
        assertThat(CedSim.entitlementGranted(claims, clock)).isFalse()
    }

    @Test
    fun `an entitled unexpired card grants the ticket`() {
        val outcome = presentSimulatedCed(keys)
        val claims = (outcome as FlowOutcome.Verified).claims.claims
        assertThat(CedSim.entitlementGranted(claims, clock)).isTrue()
    }

    @Test
    fun `the string true does not grant the entitlement`() {
        val forged =
            kotlinx.serialization.json.buildJsonObject {
                put("constant_attendance_allowance", kotlinx.serialization.json.JsonPrimitive("true"))
                put("expiry_date", kotlinx.serialization.json.JsonPrimitive("2030-12-31"))
            }
        assertThat(CedSim.entitlementGranted(forged, clock)).isFalse()
    }

    @Test
    fun `a simulated CED from an unknown federation is rejected`() {
        val impostorKeys = CedSim.generateKeys()
        val outcome = presentSimulatedCed(impostorKeys)
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.UNTRUSTED_ISSUER)
    }

    @Test
    fun `the same-device flow issues a single-use response code after verification`() {
        val outcome = presentSimulatedCed(keys, mode = FlowMode.SAME_DEVICE)
        assertThat(outcome).isInstanceOf(FlowOutcome.Verified::class.java)
        val txId = lastTransactionId()
        val redirect = flow.sameDeviceRedirectFor(txId)
        assertThat(redirect).startsWith("https://demo.zilath.example/cb/${txId.value}?response_code=")
        // Idempotent while unconsumed, single-use once exchanged.
        assertThat(flow.sameDeviceRedirectFor(txId)).isEqualTo(redirect)
        // WP_094: same-device outcomes stay pending until the user-agent comes back.
        assertThat(flow.awaitOutcome(txId)).isEqualTo(FlowOutcome.Pending)
        val code = redirect!!.substringAfter("response_code=")
        // Presented on ANOTHER LIVE transaction the code is refused AND left intact —
        // an unknown id would prove nothing, since there is no entry to update.
        val other =
            flow.start(
                PresentationRequest.forVct(CedSim.VCT, CedSim.CLAIM_PATHS, CedSim.CREDENTIAL_QUERY_ID),
                FlowMode.SAME_DEVICE,
            )
        assertThat(flow.awaitOutcome(other.id)).isEqualTo(FlowOutcome.Pending)
        assertThat(flow.consumeResponseCode(other.id, code)).isFalse()
        // ...so its own return leg still completes, exactly once.
        assertThat(flow.consumeResponseCode(txId, code)).isTrue()
        assertThat(flow.consumeResponseCode(txId, code)).isFalse()
        // A consumed code is never re-minted, and the outcome is now observable.
        assertThat(flow.sameDeviceRedirectFor(txId)).isNull()
        assertThat(flow.awaitOutcome(txId)).isInstanceOf(FlowOutcome.Verified::class.java)
    }

    @Test
    fun `the conformance outcome endpoint reports the category and never the claims`() {
        // It used to answer awaitOutcome(...).toString(), and that data class carries the
        // disclosed claims: an unauthenticated GET with a transaction id returned somebody's
        // entitlement. The harness only ever needed to know whether the run passed.
        // Cross-device: a same-device outcome deliberately reads as pending until the
        // user-agent has come back through the response-code exchange (WP_094).
        val outcome = presentSimulatedCed(keys)
        assertThat(outcome).isInstanceOf(FlowOutcome.Verified::class.java)
        val body = ConformanceController(flow, config, clock, CedSim.VCT).outcome(lastTransactionId().value)
        assertThat(body).containsEntry("outcome", "verified")
        // Nothing from inside the credential, not the claim names and not their values.
        assertThat(body.values.joinToString(" "))
            .doesNotContain("constant_attendance_allowance")
            .doesNotContain("expiry_date")
            .doesNotContain("true")
    }

    @Test
    fun `a cross-device transaction never yields a same-device redirect`() {
        presentSimulatedCed(keys)
        assertThat(flow.sameDeviceRedirectFor(lastTransactionId())).isNull()
    }

    @Test
    fun `a wallet cancellation in same-device still gets the redirect back`() {
        val request = PresentationRequest.forVct(CedSim.VCT, CedSim.CLAIM_PATHS, CedSim.CREDENTIAL_QUERY_ID)
        val started = flow.start(request, FlowMode.SAME_DEVICE)
        val outcome =
            flow.handleWalletResponse(
                started.id,
                DirectPostBody(mapOf("error" to "access_denied")),
            )
        assertThat(outcome).isInstanceOf(FlowOutcome.WalletErrorAcknowledged::class.java)
        // RPR-59: the user who cancelled in the wallet must still land back on the RP.
        assertThat(flow.sameDeviceRedirectFor(started.id)).contains("response_code=")
    }

    private fun lastTransactionId(): dev.zilath.verifier.openid4vp.TransactionId {
        // presentSimulatedCed does not expose the id: recover it from the request JWT
        // it minted (state == transaction id in this profile).
        return checkNotNull(lastStartedId) { "no transaction started" }
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
