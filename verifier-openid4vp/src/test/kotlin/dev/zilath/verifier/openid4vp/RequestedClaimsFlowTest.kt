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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.util.Base64URL
import dev.zilath.verifier.core.RejectionReason
import dev.zilath.verifier.core.TestVectors
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.security.MessageDigest

/**
 * What a query asks for decides the outcome of the protocol, not only of the verifier: a
 * presentation that does not answer it is refused, and one that does hands over what was
 * asked (OpenID4VP 1.0 §6.4.1). Before the fourth internal review a presentation disclosing
 * none of the requested claims came back Verified from the flow, and every disclosure the
 * wallet chose to make came back with it.
 *
 * The query is `forTestPid`'s: `given_name` and `family_name`. The credential discloses
 * those two and `entitled` when the wallet shows everything.
 */
class RequestedClaimsFlowTest : FlowTestSupport() {
    @Test
    fun `a presentation disclosing none of the requested claims is not satisfied`() {
        val outcome = answer(startForPid()) { false }
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.QUERY_NOT_SATISFIED)
    }

    @Test
    fun `a presentation disclosing only some of the requested claims is not satisfied`() {
        val outcome = answer(startForPid()) { it.claimName() == "given_name" }
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.QUERY_NOT_SATISFIED)
    }

    @Test
    fun `a disclosed value the query does not accept is not satisfied`() {
        val refused = answer(flow.start(familyNameRequest("Babbage"))) { true }
        assertThat((refused as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.QUERY_NOT_SATISFIED)

        // The same presentation, asked for the value it carries: only the value differed.
        val accepted = answer(flow.start(familyNameRequest("Lovelace"))) { true }
        assertThat((accepted as FlowOutcome.Verified).claims.claims.keys)
            .containsExactlyInAnyOrder("family_name", "iss", "vct")
    }

    @Test
    fun `a full disclosure hands over exactly the requested claims, iss and vct`() {
        val outcome = answer(startForPid()) { true }
        val claims = (outcome as FlowOutcome.Verified).claims.claims
        // `entitled` was disclosed, and nobody asked for it.
        assertThat(claims.keys).containsExactlyInAnyOrder("given_name", "family_name", "iss", "vct")
        assertThat(claims["family_name"]?.jsonPrimitive?.content).isEqualTo("Lovelace")
    }

    /** The outcome of answering [started] with the disclosures [disclose] keeps. */
    private fun answer(
        started: StartedTransaction,
        disclose: (JsonArray) -> Boolean,
    ): FlowOutcome {
        val body =
            walletBody(started, presentation = { nonce ->
                val issued =
                    TestVectors.vectorWith(disclose = disclose) {
                        sdClaim("given_name", "Ada")
                        sdClaim("family_name", "Lovelace")
                        sdClaim("entitled", true)
                    }
                boundTo(issued, nonce)
            })
        return flow.handleWalletResponse(started.id, body).outcome
    }

    /** A query for the test credential's `family_name`, accepting only [value]. */
    private fun familyNameRequest(value: String): PresentationRequest =
        PresentationRequest(
            buildJsonObject {
                putJsonArray("credentials") {
                    addJsonObject {
                        put("id", "pid")
                        put("format", "dc+sd-jwt")
                        putJsonObject("meta") { putJsonArray("vct_values") { add(TestVectors.VCT) } }
                        putJsonArray("claims") {
                            addJsonObject {
                                putJsonArray("path") { add("family_name") }
                                putJsonArray("values") { add(value) }
                            }
                        }
                    }
                }
            },
            "pid",
        )

    /** A disclosure's claim name: `[salt, name, value]`. */
    private fun JsonArray.claimName(): String? = if (size == 3) this[1].jsonPrimitive.content else null

    /**
     * [presentation] with its key binding signed again for [nonce]: `vectorWith` binds to
     * the fixed test nonce, and a transaction mints its own. The holder key, audience and
     * `iat` are the ones `TestVectors` uses; `sd_hash` covers the disclosures kept (RFC 9901
     * §4.3).
     */
    private fun boundTo(
        presentation: String,
        nonce: String,
    ): String {
        val presented = presentation.substringBeforeLast('~') + "~"
        val sdHash =
            Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(presented.toByteArray(Charsets.US_ASCII)))
        val header =
            JWSHeader
                .Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType(TestVectors.KB_TYP))
                .keyID(TestVectors.holderKey.keyID)
                .build()
        val claims =
            mapOf(
                "aud" to config.clientId,
                "nonce" to nonce,
                "iat" to TestVectors.NOW.epochSecond,
                "sd_hash" to sdHash.toString(),
            )
        val keyBinding = JWSObject(header, Payload(claims)).apply { sign(ECDSASigner(TestVectors.holderKey.toECKey())) }
        return presented + keyBinding.serialize()
    }
}
