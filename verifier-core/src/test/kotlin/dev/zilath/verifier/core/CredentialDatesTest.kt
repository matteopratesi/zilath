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
import java.time.Duration

/** The credential's own exp and nbf, read as numbers from the signed payload. */
class CredentialDatesTest {
    private fun rejected(detail: String) = VerificationResult.Rejected(RejectionReason.MALFORMED, detail)

    @Test
    fun `a credential without exp is malformed`() {
        // IT-Wallet 1.4.6 makes exp mandatory; without it a credential verified for ever,
        // and one without a status entry could not be stopped at all.
        assertThat(verifyPresentation(TestVectors.vector(exp = null))).isEqualTo(rejected("credential has no exp"))
    }

    @Test
    fun `an exp written in milliseconds is not a plausible date`() {
        // A year ago in milliseconds reads, as seconds, as year 57,000: it never expired.
        // Hand-made because the EUDI issuer rewrites exp through Nimbus's Date.
        val yearAgoMillis = TestVectors.NOW.minus(Duration.ofDays(365)).toEpochMilli()
        assertThat(verifyPresentation(TestVectors.handMade(mapOf("exp" to yearAgoMillis))))
            .isEqualTo(rejected("credential exp is not a plausible date"))
    }

    @Test
    fun `an exp more than fifty years ahead is not plausible, one within is`() {
        val fifty = Duration.ofDays(50L * 365)
        assertThat(verifyPresentation(TestVectors.vector(exp = TestVectors.NOW.plus(fifty).plusSeconds(1))))
            .isEqualTo(rejected("credential exp is not a plausible date"))
        assertThat(verifyPresentation(TestVectors.vector(exp = TestVectors.NOW.plus(fifty))))
            .isInstanceOf(VerificationResult.Verified::class.java)
    }

    @Test
    fun `an exp or nbf that wraps around in Nimbus is refused, not believed`() {
        // x * 1000 overflows a long: 18446745861271552 became NOW - 1 h for Nimbus, a valid
        // nbf; 18446745861278752 became NOW + 1 h, a valid exp, for a number that means no
        // date at all. Negative values are refused alongside.
        listOf<Number>(18_446_745_861_278_752L, -1L, 1.0e30, Double.MAX_VALUE).forEach {
            assertThat(verifyPresentation(TestVectors.handMade(mapOf("exp" to it))))
                .`as`(it.toString())
                .isEqualTo(rejected("credential exp is not a plausible date"))
        }
        assertThat(verifyPresentation(TestVectors.handMade(mapOf("nbf" to 18_446_745_861_271_552L))))
            .isEqualTo(rejected("credential nbf is not a plausible date"))
        assertThat(verifyPresentation(TestVectors.handMade(mapOf("exp" to null))))
            .isEqualTo(rejected("credential exp is not a plausible date"))
        // The same envelope with ordinary dates verifies: the rejections above are the numbers.
        assertThat(
            verifyPresentation(TestVectors.handMade(mapOf("nbf" to TestVectors.NOW.minusSeconds(60).epochSecond))),
        ).isInstanceOf(VerificationResult.Verified::class.java)
    }

    @Test
    fun `a fractional exp is read to the second`() {
        // RFC 7519 §2 allows non-integer NumericDates.
        val inAnHour = TestVectors.NOW.plusSeconds(3600).epochSecond + 0.5
        assertThat(verifyPresentation(TestVectors.handMade(mapOf("exp" to inAnHour))))
            .isInstanceOf(VerificationResult.Verified::class.java)
    }
}
