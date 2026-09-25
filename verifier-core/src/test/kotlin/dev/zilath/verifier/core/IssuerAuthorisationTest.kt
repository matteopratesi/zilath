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

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.ZoneOffset

class IssuerAuthorisationTest {
    private val verifier = SdJwtVcCredentialVerifier()

    private fun verifyUnder(credentialTypes: Set<String>?): VerificationResult =
        verifier.verify(
            RawPresentation.SdJwtVcPresentation(TestVectors.vector()),
            VerificationContext(
                expectedNonce = TestVectors.NONCE,
                expectedAudiences = setOf(TestVectors.AUDIENCE),
                clock = Clock.fixed(TestVectors.NOW, ZoneOffset.UTC),
                trustEvaluator = {
                    TrustDecision.Trusted(listOf(TestVectors.issuerEcKey.toPublicJWK()), credentialTypes)
                },
                statusChecker = { _, _ -> CredentialStatus.UNKNOWN },
            ),
        )

    @Test
    fun `an issuer trusted for other types cannot issue this one`() {
        val result = verifyUnder(setOf("urn:zilath:test:something-else"))
        assertThat(result).isEqualTo(
            VerificationResult.Rejected(
                RejectionReason.UNTRUSTED_ISSUER,
                "issuer is not authorised for this credential type",
            ),
        )
        assertThat(verifyUnder(emptySet())).isInstanceOf(VerificationResult.Rejected::class.java)
    }

    @Test
    fun `an issuer trusted for this type, or for any, verifies`() {
        assertThat(verifyUnder(setOf(TestVectors.VCT))).isInstanceOf(VerificationResult.Verified::class.java)
        assertThat(verifyUnder(null)).isInstanceOf(VerificationResult.Verified::class.java)
    }
}
