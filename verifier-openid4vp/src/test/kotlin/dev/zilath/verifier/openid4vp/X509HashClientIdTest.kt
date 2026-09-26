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

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.CredentialStatus
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.TrustEvaluator
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.junit.jupiter.api.Test
import java.time.Clock

/**
 * An `x509_hash` client id is the hash of the certificate the request object carries in
 * `x5c` (OpenID4VP 1.0 §5.9.3): a relying party that cannot send that certificate, or
 * whose client id hashes another one, is refused when it is configured rather than by
 * every wallet it meets.
 */
class X509HashClientIdTest {
    private fun signingKey(): ECKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate()

    private fun config(
        clientId: String,
        signingKey: ECKey,
    ) = RelyingPartyConfiguration(
        clientId = clientId,
        endpoints = RpEndpoints("https://rp.example/openid4vp/request", "https://rp.example/openid4vp/response"),
        keys = RpKeys(requestSigningKey = signingKey),
        trustEvaluator = TrustEvaluator { TrustDecision.Untrusted("x509 test") },
        statusChecker = StatusChecker { _, _ -> CredentialStatus.UNKNOWN },
    )

    @Test
    fun `an x509_hash client id needs a certificate chain on the request signing key`() {
        val withoutChain = signingKey()
        val clientId = x509HashClientIdOf(withSelfSignedCertificate(withoutChain))
        assertThatIllegalArgumentException()
            .isThrownBy { config(clientId, withoutChain) }
            .withMessageContaining("requires an x5c certificate chain")
    }

    @Test
    fun `an x509_hash client id must be the hash of the signing key's own certificate`() {
        val someoneElse = x509HashClientIdOf(withSelfSignedCertificate(signingKey()))
        assertThatIllegalArgumentException()
            .isThrownBy { config(someoneElse, withSelfSignedCertificate(signingKey())) }
            .withMessageContaining("hash of the request signing key's leaf certificate")
    }

    @Test
    fun `the hash of the leaf certificate is accepted, and the request object carries the chain`() {
        val key = withSelfSignedCertificate(signingKey())
        val flow =
            OpenId4VpVerificationFlow.withInMemoryStore(
                config(x509HashClientIdOf(key), key),
                SdJwtVcCredentialVerifier(),
                Clock.systemUTC(),
            )
        flow.use {
            val started = it.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))
            val header = SignedJWT.parse(it.requestJwtFor(started.id)).header
            assertThat(header.x509CertChain).isEqualTo(key.x509CertChain)
        }
    }
}
