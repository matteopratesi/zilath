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

/**
 * The key binding `iat` window: [VerificationContext.keyBindingMaxAge] on either side of
 * now, both bounds included. Before the fourth internal review only the past side was
 * pinned — removing the `abs()` that makes the window two-sided left every test green, and
 * a key binding dated an hour ahead would have verified.
 */
class KeyBindingWindowTest {
    private val maxAge = VerificationContext.DEFAULT_KEY_BINDING_MAX_AGE

    private fun resultAt(kbIssuedAt: java.time.Instant) =
        verifyPresentation(TestVectors.vector(kbIssuedAt = kbIssuedAt))

    private val outsideWindow =
        VerificationResult.Rejected(RejectionReason.INVALID_KEY_BINDING, "key binding iat outside the accepted window")

    @Test
    fun `a key binding dated in the future is rejected`() {
        assertThat(resultAt(TestVectors.NOW.plusSeconds(3600))).isEqualTo(outsideWindow)
    }

    @Test
    fun `the window includes both of its bounds and nothing beyond`() {
        assertThat(resultAt(TestVectors.NOW.plus(maxAge))).isInstanceOf(VerificationResult.Verified::class.java)
        assertThat(resultAt(TestVectors.NOW.minus(maxAge))).isInstanceOf(VerificationResult.Verified::class.java)
        assertThat(resultAt(TestVectors.NOW.plus(maxAge).plusSeconds(1))).isEqualTo(outsideWindow)
        assertThat(resultAt(TestVectors.NOW.minus(maxAge).minusSeconds(1))).isEqualTo(outsideWindow)
    }

    @Test
    fun `the window follows the configured maximum age`() {
        val ctx = testContext(keyBindingMaxAge = Duration.ofSeconds(30))
        assertThat(verifyPresentation(TestVectors.vector(kbIssuedAt = TestVectors.NOW.plusSeconds(31)), ctx))
            .isEqualTo(outsideWindow)
        assertThat(verifyPresentation(TestVectors.vector(kbIssuedAt = TestVectors.NOW.minusSeconds(30)), ctx))
            .isInstanceOf(VerificationResult.Verified::class.java)
    }
}
