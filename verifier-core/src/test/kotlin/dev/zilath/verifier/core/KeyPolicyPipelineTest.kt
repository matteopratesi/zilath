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

import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * The single key rule ([acceptableJwsVerifierFor]: RSA from 3072 bits, EC on the NIST
 * curves) as the pipeline applies it. The fourth internal review verified complete
 * presentations under 512- and 1024-bit RSA issuer keys: RFC 7518 §3.3 says 2048 bits or
 * larger MUST be used, and a 512-bit modulus factors in hours. IT-Wallet 1.4.7 raised the
 * bar (test ATT-006: 128 bits of security strength, 3072 bits for RSA), so a 2048-bit key is
 * refused too, and every refusal here has its acceptance under a 3072-bit key beside it.
 */
class KeyPolicyPipelineTest {
    @Test
    fun `an issuer signature under an rsa key below 3072 bits does not verify`() {
        // 512 bits is out of this loop: a PS256 signature needs a modulus of at least 528 bits
        // (RFC 8017 §9.1.1), so no such key can sign one. SharedRulesTest has the 512-bit key.
        for (bits in listOf(768, 1024, 2048)) {
            val weak = weakRsaKey(bits)
            val result =
                verifyPresentation(
                    TestVectors.vector(issuerSigningKey = weak),
                    testContext(trust = TestVectors.trustIssuer(weak)),
                )
            assertThat(result)
                .`as`("$bits bits")
                .isEqualTo(
                    VerificationResult.Rejected(
                        RejectionReason.INVALID_ISSUER_SIGNATURE,
                        "issuer signature does not verify",
                    ),
                )
        }
    }

    @Test
    fun `an issuer signature under a 3072 bit rsa key verifies`() {
        val strong = RSAKeyGenerator(3072).generate()
        val result =
            verifyPresentation(
                TestVectors.vector(issuerSigningKey = strong),
                testContext(trust = TestVectors.trustIssuer(strong)),
            )
        assertThat(result).isInstanceOf(VerificationResult.Verified::class.java)
    }

    @Test
    fun `an rsa holder key below 3072 bits cannot bind a presentation`() {
        // The cnf key is the issuer's statement, but a key binding under a factorable key is
        // a signature anyone can make: whoever factors it presents the credential as theirs.
        for (bits in listOf(1024, 2048)) {
            val weak = weakRsaKey(bits)
            val result = verifyPresentation(TestVectors.vector(holderSigningKey = weak))
            assertThat(result)
                .`as`("$bits bits")
                .isEqualTo(
                    VerificationResult.Rejected(RejectionReason.INVALID_KEY_BINDING, "key binding does not verify"),
                )
        }
    }

    @Test
    fun `a 3072 bit rsa holder key binds a presentation`() {
        val strong = RSAKeyGenerator(3072).keyID("holder-rsa").generate()
        assertThat(verifyPresentation(TestVectors.vector(holderSigningKey = strong)))
            .isInstanceOf(VerificationResult.Verified::class.java)
    }
}
