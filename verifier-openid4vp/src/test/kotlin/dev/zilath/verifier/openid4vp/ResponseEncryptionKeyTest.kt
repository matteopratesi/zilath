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
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.RejectionReason
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * Each transaction's response is encrypted to a key of its own. Before the fourth internal
 * review one long-lived key encrypted every response of the relying party's life, so a key
 * stolen once opened every response ever captured.
 */
class ResponseEncryptionKeyTest : FlowTestSupport() {
    private fun publishedKeyOf(
        started: StartedTransaction,
        source: VerificationFlow = flow,
    ): JWK {
        val jar = SignedJWT.parse(checkNotNull(source.requestJwtFor(started.id)))
        val jwks = jar.jwtClaimsSet.getJSONObjectClaim("client_metadata")["jwks"] as Map<*, *>
        assertThat(jwks["keys"] as List<*>).hasSize(1)
        return advertisedEncryptionKey(jar.jwtClaimsSet.getJSONObjectClaim("client_metadata"))
    }

    @Test
    fun `every transaction publishes an encryption key of its own`() {
        val first = publishedKeyOf(startForPid()).toECKey()
        val second = publishedKeyOf(startForPid()).toECKey()
        assertThat(first.keyID).isNotEqualTo(second.keyID).isNotEqualTo(encryptionKey.keyID)
        assertThat(first.x).isNotEqualTo(second.x)
        assertThat(first.x).isNotEqualTo(encryptionKey.x)
        for (key in listOf(first, second)) {
            assertThat(key.isPrivate).isFalse()
            assertThat(key.keyUse?.value).isEqualTo("enc")
            assertThat(key.algorithm?.name).isEqualTo("ECDH-ES")
        }
    }

    @Test
    fun `a response encrypted to another transaction's key is refused`() {
        val first = startForPid()
        val second = startForPid()
        val firstKey = publishedKeyOf(first)
        val named = walletBody(second, encryptTo = firstKey, jweHeader = headerWithKid(firstKey.keyID))
        assertThat((flow.handleWalletResponse(second.id, named).outcome as FlowOutcome.Rejected).reason)
            .isEqualTo(RejectionReason.MALFORMED)
        val third = startForPid()
        val unnamed = walletBody(third, encryptTo = firstKey)
        assertThat((flow.handleWalletResponse(third.id, unnamed).outcome as FlowOutcome.Rejected).reason)
            .isEqualTo(RejectionReason.MALFORMED)
    }

    @Test
    fun `the static key is accepted only when configured as the fallback`() {
        // Configured (FlowTestSupport sets one): a wallet that encrypted to the key it
        // resolved from the federation, not the request's, is still served.
        val withFallback = startForPid()
        val toStatic = walletBody(withFallback, encryptTo = encryptionKey.toPublicJWK())
        assertThat(flow.handleWalletResponse(withFallback.id, toStatic).outcome)
            .isInstanceOf(FlowOutcome.Verified::class.java)

        val ephemeralOnly =
            OpenId4VpVerificationFlow.withInMemoryStore(
                config.copy(keys = RpKeys(requestSigningKey = signingKey)),
                SdJwtVcCredentialVerifier(),
                clock,
            )
        val started = ephemeralOnly.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        val refused = walletBody(started, encryptTo = encryptionKey.toPublicJWK(), source = ephemeralOnly)
        assertThat((ephemeralOnly.handleWalletResponse(started.id, refused).outcome as FlowOutcome.Rejected).reason)
            .isEqualTo(RejectionReason.MALFORMED)
        val accepted = ephemeralOnly.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        assertThat(
            ephemeralOnly.handleWalletResponse(accepted.id, walletBody(accepted, source = ephemeralOnly)).outcome,
        ).isInstanceOf(FlowOutcome.Verified::class.java)
    }

    @Test
    fun `the private key leaves the store with the response, and at expiry`() {
        val retaining = RetainingTransactionStore()
        val retainingFlow = OpenId4VpVerificationFlow(config, SdJwtVcCredentialVerifier(), retaining, clock)

        val answered = retainingFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        assertThat(retaining.get(answered.id)?.responseEncryptionKey?.isPrivate).isTrue()
        retainingFlow.handleWalletResponse(answered.id, walletBody(answered, source = retainingFlow))
        assertThat(retaining.get(answered.id)?.responseEncryptionKey).isNull()

        val abandoned = retainingFlow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
        clock.advance(config.transactionTimeToLive.plusSeconds(1))
        assertThat(retainingFlow.awaitOutcome(abandoned.id, abandoned.pollToken)).isEqualTo(FlowOutcome.Expired)
        assertThat(retaining.get(abandoned.id)?.responseEncryptionKey).isNull()
    }

    @Test
    fun `a JWE kid must name the key it was encrypted to`() {
        // OpenID4VP 1.0 §8.3: the wallet MUST echo the kid of the key it selected. A foreign
        // kid on a JWE that decrypts with our key used to go unnoticed.
        val foreign = startForPid()
        val mislabelled = walletBody(foreign, jweHeader = headerWithKid("some-other-key"))
        val refused = flow.handleWalletResponse(foreign.id, mislabelled).outcome as FlowOutcome.Rejected
        assertThat(refused.reason).isEqualTo(RejectionReason.MALFORMED)
        assertThat(refused.detail).isEqualTo("response JWE kid names no key of this transaction")

        val named = startForPid()
        val labelled = walletBody(named, jweHeader = headerWithKid(publishedKeyOf(named).keyID))
        assertThat(flow.handleWalletResponse(named.id, labelled).outcome).isInstanceOf(FlowOutcome.Verified::class.java)

        // No kid at all stays accepted: wallets that omit it exist, and decryption proves the key.
        val bare = startForPid()
        assertThat(flow.handleWalletResponse(bare.id, walletBody(bare)).outcome)
            .isInstanceOf(FlowOutcome.Verified::class.java)
    }

    private fun headerWithKid(kid: String): JWEHeader =
        JWEHeader
            .Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
            .keyID(kid)
            .build()
}
