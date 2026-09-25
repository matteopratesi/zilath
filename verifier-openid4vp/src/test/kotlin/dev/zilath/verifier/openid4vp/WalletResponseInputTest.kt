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

import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import dev.zilath.verifier.core.RejectionReason
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

/** What the unauthenticated response endpoint accepts, and in what shape and size. */
class WalletResponseInputTest : FlowTestSupport() {
    @Test
    fun `missing response parameter is rejected as malformed`() {
        val started = startForPid()
        val outcome = flow.handleWalletResponse(started.id, DirectPostBody(emptyMap())).outcome
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.MALFORMED)
    }

    @Test
    fun `garbage response is rejected as malformed`() {
        val started = startForPid()
        val outcome = flow.handleWalletResponse(started.id, DirectPostBody(mapOf("response" to "not-a-jwe"))).outcome
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.MALFORMED)
    }

    @Test
    fun `response encrypted to the wrong key is rejected as malformed`() {
        val started = startForPid()
        val wrongKey = ECKeyGenerator(Curve.P_256).keyID("wrong").generate().toPublicJWK()
        val outcome = flow.handleWalletResponse(started.id, walletBody(started, encryptTo = wrongKey)).outcome
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.MALFORMED)
    }

    @Test
    fun `a response using an encryption the RP never advertised is rejected`() {
        // ECDHDecrypter would accept every one of these; the RP's metadata advertises none
        // of them, and a compressed payload on an unauthenticated endpoint is a
        // decompression bomb. What is advertised is what is accepted.
        val notAdvertised =
            listOf(
                JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128CBC_HS256),
                JWEHeader(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM),
                JWEHeader
                    .Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                    .compressionAlgorithm(CompressionAlgorithm.DEF)
                    .build(),
            )
        for (header in notAdvertised) {
            val started = startForPid()
            val outcome = flow.handleWalletResponse(started.id, walletBody(started, jweHeader = header)).outcome
            assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.MALFORMED)
        }
    }

    @Test
    fun `the advertised A128GCM alternative is accepted`() {
        val started = startForPid()
        val body = walletBody(started, jweHeader = JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM))
        assertThat(flow.handleWalletResponse(started.id, body).outcome).isInstanceOf(FlowOutcome.Verified::class.java)
    }

    @Test
    fun `vp_token carries exactly one presentation for the query`() {
        // OpenID4VP 1.0 §8.1: without `multiple` the array MUST hold one presentation, and
        // §14.1.2 wants every presentation in a response validated. The first element used
        // to be verified and the rest dropped unseen — here the second is not even ours.
        val two = startForPid()
        val extra =
            flow
                .handleWalletResponse(
                    two.id,
                    walletBody(two, vpToken = { compact ->
                        buildJsonObject {
                            put(
                                "pid",
                                buildJsonArray {
                                    add(compact)
                                    add("not-a-presentation")
                                },
                            )
                        }
                    }),
                ).outcome
        assertThat((extra as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.MALFORMED)
        assertThat(extra.detail).isEqualTo("vp_token carries more presentations than requested")

        val empty = startForPid()
        val none =
            flow
                .handleWalletResponse(
                    empty.id,
                    walletBody(empty, vpToken = { buildJsonObject { put("pid", buildJsonArray { }) } }),
                ).outcome
        assertThat((none as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.MALFORMED)

        // IT-Wallet WP_093: the single presentation may also come without the array.
        val single = startForPid()
        val unwrapped =
            flow
                .handleWalletResponse(
                    single.id,
                    walletBody(single, vpToken = { compact -> buildJsonObject { put("pid", compact) } }),
                ).outcome
        assertThat(unwrapped).isInstanceOf(FlowOutcome.Verified::class.java)
    }

    @Test
    fun `a bare vp_token string is the legacy shape, refused under IT-Wallet`() {
        // IT-Wallet: the vp_token MUST be a JSON object keyed by credential query id. The
        // ARF baseline profile keeps the pre-1.0 form (see the ARF profile test below).
        val started = startForPid()
        val outcome =
            flow
                .handleWalletResponse(
                    started.id,
                    walletBody(started, vpToken = { JsonPrimitive(it) }),
                ).outcome
        assertThat((outcome as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.MALFORMED)
        assertThat(ItWalletProfile.acceptsBareVpToken).isFalse()
        assertThat(ArfBaselineProfile.acceptsBareVpToken).isTrue()
    }

    @Test
    fun `a response above the size limit is refused before it is decoded`() {
        // The size used to be bounded only by the servlet container: a JWE of several MiB,
        // encrypted to the RP's published key, was decoded, decrypted and parsed in full.
        // Two configurations over one store: one to start transactions, one with a limit.
        val decoded =
            java.util.concurrent.atomic
                .AtomicInteger()
        val counting =
            object : WalletProfile by ItWalletProfile {
                override fun decodeWalletResponse(
                    body: DirectPostBody,
                    config: RelyingPartyConfiguration,
                ): JsonObject = ItWalletProfile.decodeWalletResponse(body, config).also { decoded.incrementAndGet() }
            }
        val store = InMemoryTransactionStore(clock)
        val starter = OpenId4VpVerificationFlow(config, SdJwtVcCredentialVerifier(), store, clock)

        fun limitedTo(max: Int) =
            OpenId4VpVerificationFlow(
                config.copy(profile = counting, maxWalletResponseLength = max),
                SdJwtVcCredentialVerifier(),
                store,
                clock,
            )

        fun lengthOf(body: DirectPostBody) = body.parameters.entries.sumOf { it.key.length + it.value.length }

        val over = starter.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        val overBody = walletBody(over, source = starter)
        val refused = limitedTo(lengthOf(overBody) - 1).handleWalletResponse(over.id, overBody).outcome
        assertThat((refused as FlowOutcome.Rejected).reason).isEqualTo(RejectionReason.MALFORMED)
        assertThat(refused.detail).isEqualTo("wallet response exceeds the size limit")
        assertThat(decoded.get()).isZero()

        val at = starter.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        val atBody = walletBody(at, source = starter)
        assertThat(limitedTo(lengthOf(atBody)).handleWalletResponse(at.id, atBody).outcome)
            .isInstanceOf(FlowOutcome.Verified::class.java)
        assertThat(decoded.get()).isEqualTo(1)

        assertThat(RelyingPartyConfiguration.DEFAULT_MAX_WALLET_RESPONSE_LENGTH).isEqualTo(1024 * 1024)
        assertThatThrownBy { config.copy(maxWalletResponseLength = 0) }
            .isInstanceOf(IllegalArgumentException::class.java)
    }

    @Test
    fun `the wallet's error text is bounded before the transaction keeps it`() {
        // Anyone holding a transaction id can post an error, and its text lives in the
        // store for the whole time to live. It used to be kept verbatim at whatever size the
        // container accepted: a million characters stayed a million characters.
        val flood = startForPid()
        val huge = "e".repeat(1_000_000)
        val flooded =
            flow
                .handleWalletResponse(
                    flood.id,
                    DirectPostBody(mapOf("error" to huge, "error_description" to huge)),
                ).outcome
        val kept = flow.awaitOutcome(flood.id, flood.pollToken) as FlowOutcome.WalletErrorAcknowledged
        assertThat(kept).isEqualTo(flooded)
        assertThat(kept.error).isEqualTo(FlowOutcome.WalletErrorAcknowledged.MALFORMED_ERROR)
        assertThat(kept.description).hasSize(MAX_ERROR_DESCRIPTION_LENGTH)

        // Outside the RFC 6749 character set: a code with a line break is no code, and a
        // description keeps its length with the offending characters replaced.
        val forged = startForPid()
        val injected =
            flow
                .handleWalletResponse(
                    forged.id,
                    DirectPostBody(
                        mapOf(
                            "error" to "access_denied\r\nX",
                            "error_description" to "line\r\n2026-09-04 WARN forged \"quote\" \\ ok",
                        ),
                    ),
                ).outcome as FlowOutcome.WalletErrorAcknowledged
        assertThat(injected.error).isEqualTo(FlowOutcome.WalletErrorAcknowledged.MALFORMED_ERROR)
        assertThat(injected.description).isEqualTo("line??2026-09-04 WARN forged ?quote? ? ok")

        // A description with nothing printable left is no description.
        val blank = startForPid()
        val control =
            flow
                .handleWalletResponse(
                    blank.id,
                    DirectPostBody(
                        mapOf(
                            "error" to "access_denied",
                            "error_description" to " ",
                        ),
                    ),
                ).outcome
        assertThat(control).isEqualTo(FlowOutcome.WalletErrorAcknowledged("access_denied", null))
    }
}
