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
package dev.zilath.verifier.openid4vp

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.CredentialStatus
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TestVectors
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.assertj.core.api.Assertions.assertThat

/**
 * The relying party, flow and simulated wallet the flow tests share: a fresh set per test
 * instance, with a clock that moves only when told to.
 */
abstract class FlowTestSupport {
    protected val signingKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate()
    protected val encryptionKey = ECKeyGenerator(Curve.P_256).keyID("rp-enc").generate()
    protected val clock = SteppingClock(TestVectors.NOW)
    protected val config =
        RelyingPartyConfiguration(
            clientId = TestVectors.AUDIENCE,
            endpoints =
                RpEndpoints(
                    requestUriBase = "https://rp.example/openid4vp/request",
                    responseUriBase = "https://rp.example/openid4vp/response",
                    sameDeviceCallbackBase = "https://rp.example/cb",
                ),
            keys = RpKeys(requestSigningKey = signingKey, responseEncryptionKey = encryptionKey),
            trustEvaluator = TestVectors.trustIssuerEc(),
            statusChecker = StatusChecker { _, _ -> CredentialStatus.VALID },
        )
    protected val flow =
        OpenId4VpVerificationFlow.withInMemoryStore(config, SdJwtVcCredentialVerifier(), clock)

    /**
     * Simulated wallet: fetches the request object exactly like a wallet would, verifies
     * its signature, then answers with an SD-JWT VC presentation encrypted to the RP key
     * advertised in `client_metadata` (IT-Wallet `direct_post.jwt` profile). [presentation],
     * given the nonce the key binding must carry, replaces the default presentation.
     */
    @Suppress("LongParameterList") // test factory: independent, defaulted axes
    protected fun walletBody(
        started: StartedTransaction,
        nonceOverride: String? = null,
        stateOverride: String? = null,
        vpToken: (String) -> JsonElement = ::onePresentationForPid,
        encryptTo: JWK? = null,
        audienceOverride: String? = null,
        jweHeader: JWEHeader = JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM),
        vct: String = TestVectors.VCT,
        echoedNonce: String? = null,
        source: VerificationFlow = flow,
        presentation: ((nonce: String) -> String)? = null,
    ): DirectPostBody {
        val jar = checkNotNull(source.requestJwtFor(started.id)) { "request JWT not available" }
        val jwt = SignedJWT.parse(jar)
        assertThat(jwt.verify(ECDSAVerifier(signingKey.toPublicJWK()))).isTrue()
        val claims = jwt.jwtClaimsSet
        val advertisedKey = advertisedEncryptionKey(claims.getJSONObjectClaim("client_metadata"))
        val nonce = nonceOverride ?: claims.getStringClaim("nonce")
        val compact =
            presentation?.invoke(nonce)
                ?: TestVectors.vector(nonce = nonce, audience = audienceOverride ?: config.clientId, vct = vct)
        val payload =
            buildJsonObject {
                put("vp_token", vpToken(compact))
                put("state", stateOverride ?: claims.getStringClaim("state"))
                echoedNonce?.let { put("nonce", it) }
            }
        val jwe = JWEObject(jweHeader, Payload(payload.toString()))
        jwe.encrypt(ECDHEncrypter((encryptTo ?: advertisedKey).toECKey()))
        return DirectPostBody(mapOf("response" to jwe.serialize()))
    }

    protected fun onePresentationForPid(compact: String): JsonElement =
        buildJsonObject { put("pid", buildJsonArray { add(compact) }) }

    protected fun advertisedEncryptionKey(clientMetadata: Map<String, Any?>): JWK {
        val jwks = clientMetadata["jwks"] as Map<*, *>
        val keys = jwks["keys"] as List<*>

        @Suppress("UNCHECKED_CAST")
        return JWK.parse(JSONObjectUtils.toJSONString(keys.first() as Map<String, Any?>))
    }

    protected fun startForPid(): StartedTransaction =
        flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
}
