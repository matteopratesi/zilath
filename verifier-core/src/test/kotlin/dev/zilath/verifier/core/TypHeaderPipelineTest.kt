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

/**
 * The `typ` headers as the pipeline compares them: RFC 7515 §4.1.9 equivalence through
 * [mediaTypeMatches], absence tolerated (see `checkTypIfPresent`), any other type refused.
 * Before the fourth internal review the comparison was literal, so `application/dc+sd-jwt`
 * — the same media type — was refused, and no test presented a key binding JWT with a
 * wrong `typ` at all: removing that check left the whole suite green.
 */
class TypHeaderPipelineTest {
    @Test
    fun `the issuer typ forms rfc 7515 makes equivalent verify`() {
        listOf("dc+sd-jwt", "application/dc+sd-jwt", "DC+SD-JWT", "vc+sd-jwt", "application/vc+sd-jwt").forEach {
            assertThat(verifyPresentation(TestVectors.vector(issuerTyp = it)))
                .`as`(it)
                .isInstanceOf(VerificationResult.Verified::class.java)
        }
    }

    @Test
    fun `an issuer jwt of another type is refused`() {
        listOf("JWT", "application/jwt", "dc+sd-jwt;x=1", "foo/dc+sd-jwt", "kb+jwt", "statuslist+jwt").forEach {
            assertThat(verifyPresentation(TestVectors.vector(issuerTyp = it)))
                .`as`(it)
                .isEqualTo(VerificationResult.Rejected(RejectionReason.UNSUPPORTED_FORMAT, "unexpected typ header"))
        }
    }

    @Test
    fun `the key binding typ forms rfc 7515 makes equivalent verify`() {
        listOf("kb+jwt", "application/kb+jwt", "KB+JWT").forEach {
            assertThat(verifyPresentation(TestVectors.vector(kbTyp = it)))
                .`as`(it)
                .isInstanceOf(VerificationResult.Verified::class.java)
        }
    }

    @Test
    fun `a key binding jwt of another type is refused`() {
        // RFC 9901 §4.3: typ MUST be kb+jwt. The EUDI library would check it, but the
        // pipeline replaces its key binding processor, so this is the only place it happens.
        listOf("JWT", "application/jwt", "kb+jwt;x=1", "dc+sd-jwt").forEach {
            assertThat(verifyPresentation(TestVectors.vector(kbTyp = it)))
                .`as`(it)
                .isEqualTo(VerificationResult.Rejected(RejectionReason.INVALID_KEY_BINDING, "unexpected typ header"))
        }
    }

    @Test
    fun `a key binding jwt without typ is tolerated, as documented`() {
        // Deliberate (checkTypIfPresent): aud, nonce, sd_hash and the cnf key already make
        // a substituted JWT useless, and rejecting on absence would cost holders nothing
        // is known to protect.
        assertThat(
            verifyPresentation(TestVectors.vector(kbTyp = null)),
        ).isInstanceOf(VerificationResult.Verified::class.java)
    }
}
