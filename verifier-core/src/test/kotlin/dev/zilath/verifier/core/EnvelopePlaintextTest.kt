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

import eu.europa.ec.eudi.sdjwt.DisclosableObjectSpecBuilder
import eu.europa.ec.eudi.sdjwt.cnf
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * SD-JWT VC §3.2.2.2: `iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity` and `status` MUST
 * NOT be selectively disclosed. The pipeline reads them from the signed payload, where a
 * disclosed claim is only a digest: before the fourth internal review a `status` behind a
 * disclosure never reached the status checker, and an `exp` behind one never expired.
 */
class EnvelopePlaintextTest {
    private val sdEnvelope =
        VerificationResult.Rejected(
            RejectionReason.MALFORMED,
            "a claim that must be in plaintext is selectively disclosed",
        )

    /** A status checker that says REVOKED and counts its calls. */
    private class RevokingChecker : StatusChecker {
        var calls = 0

        override fun check(
            statusRef: StatusReference,
            trust: StatusIssuerTrust,
        ): CredentialStatus = CredentialStatus.REVOKED.also { calls++ }
    }

    /** The plaintext envelope, minus the claims [except] names: the test writes those itself. */
    private fun DisclosableObjectSpecBuilder.envelope(vararg except: String) {
        if ("iss" !in except) claim("iss", TestVectors.ISSUER)
        claim("iat", TestVectors.NOW.minusSeconds(600).epochSecond)
        if ("exp" !in except) claim("exp", TestVectors.NOW.plusSeconds(3600).epochSecond)
        if ("vct" !in except) claim("vct", TestVectors.VCT)
        cnf(TestVectors.holderKey.toPublicJWK())
        sdClaim("given_name", "Ada")
    }

    @Test
    fun `a status behind a disclosure is rejected before any status check`() {
        val checker = RevokingChecker()
        val compact =
            TestVectors.vectorWith(plaintextEnvelope = false) {
                envelope()
                sdObjClaim("status") {
                    objClaim("status_list") {
                        claim("idx", 3)
                        claim("uri", "https://status.example/1")
                    }
                }
            }
        assertThat(verifyPresentation(compact, testContext(status = checker))).isEqualTo(sdEnvelope)
        assertThat(checker.calls).isZero()
    }

    @Test
    fun `a status_list behind a disclosure inside a plaintext status is rejected too`() {
        val compact =
            TestVectors.vectorWith(plaintextEnvelope = false) {
                envelope()
                objClaim("status") {
                    sdObjClaim("status_list") {
                        claim("idx", 3)
                        claim("uri", "https://status.example/1")
                    }
                }
            }
        assertThat(verifyPresentation(compact, testContext(status = RevokingChecker()))).isEqualTo(sdEnvelope)
    }

    @Test
    fun `an exp behind a disclosure is rejected, and a withheld one leaves none`() {
        val past = TestVectors.NOW.minusSeconds(86_400).epochSecond
        val disclosed =
            TestVectors.vectorWith(plaintextEnvelope = false) {
                envelope("exp")
                sdClaim("exp", past)
            }
        assertThat(verifyPresentation(disclosed)).isEqualTo(sdEnvelope)
        val withheld =
            TestVectors.vectorWith(disclose = { it.getOrNull(1)?.toString() != "\"exp\"" }, plaintextEnvelope = false) {
                envelope("exp")
                sdClaim("exp", past)
            }
        assertThat(verifyPresentation(withheld))
            .isEqualTo(VerificationResult.Rejected(RejectionReason.MALFORMED, "credential has no exp"))
    }

    @Test
    fun `an nbf, vct or iss behind a disclosure is rejected`() {
        val future = TestVectors.NOW.plusSeconds(86_400).epochSecond
        val nbf =
            TestVectors.vectorWith(plaintextEnvelope = false) {
                envelope()
                sdClaim("nbf", future)
            }
        val vct =
            TestVectors.vectorWith(plaintextEnvelope = false) {
                envelope("vct")
                sdClaim("vct", TestVectors.VCT)
            }
        val iss =
            TestVectors.vectorWith(plaintextEnvelope = false) {
                envelope("iss")
                sdClaim("iss", TestVectors.ISSUER)
            }
        for (compact in listOf(nbf, vct, iss)) {
            assertThat(verifyPresentation(compact)).isEqualTo(sdEnvelope)
        }
    }

    @Test
    fun `the same envelope in plaintext verifies and reaches the status checker`() {
        val checker = RevokingChecker()
        val compact =
            TestVectors.vectorWith(plaintextEnvelope = false) {
                envelope()
                objClaim("status") {
                    objClaim("status_list") {
                        claim("idx", 3)
                        claim("uri", "https://status.example/1")
                    }
                }
            }
        assertThat(verifyPresentation(compact, testContext(status = checker)))
            .isEqualTo(VerificationResult.Rejected(RejectionReason.REVOKED, "credential is revoked"))
        assertThat(checker.calls).isOne()
    }
}
