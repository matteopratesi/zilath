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

import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.json.jsonPrimitive
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/** What the key binding JWT must say, beyond its signature: sd_hash, aud, iat. */
class KeyBindingClaimsTest {
    private val doesNotVerify =
        VerificationResult.Rejected(RejectionReason.INVALID_KEY_BINDING, "key binding does not verify")

    @Test
    fun `credentials issued with sha-256, sha-384 and sha-512 all verify`() {
        // RFC 9901 §4.3: sd_hash uses the algorithm _sd_alg names. Zilath recomputed it in
        // SHA-256 whatever _sd_alg said, and rejected every genuine sha-384 or sha-512
        // presentation as the wallet's fault (fourth internal review).
        listOf("sha-256", "sha-384", "sha-512").forEach {
            assertThat(verifyPresentation(TestVectors.vector(sdAlg = it)))
                .`as`(it)
                .isInstanceOf(VerificationResult.Verified::class.java)
        }
    }

    @Test
    fun `an sd_hash computed with another algorithm than _sd_alg is rejected`() {
        // The EUDI library's own sd_hash check still bites without Zilath's recomputation.
        assertThat(verifyPresentation(TestVectors.vector(sdAlg = "sha-384", kbSdHashAlg = "sha-256")))
            .isEqualTo(doesNotVerify)
        assertThat(verifyPresentation(TestVectors.vector(sdAlg = "sha-256", kbSdHashAlg = "sha-512")))
            .isEqualTo(doesNotVerify)
    }

    @Test
    fun `a disclosure withheld after the key binding was signed breaks the sd_hash`() {
        val parts = TestVectors.vector().split('~').toMutableList()
        parts.removeAt(1)
        assertThat(verifyPresentation(parts.joinToString("~"))).isEqualTo(doesNotVerify)
    }

    @Test
    fun `without _sd_alg the digests and sd_hash are sha-256`() {
        val compact =
            TestVectors.handMade(disclosures = listOf("""["c2FsdA","given_name","Ada"]"""), omitted = setOf("_sd_alg"))
        val result = verifyPresentation(compact) as VerificationResult.Verified
        assertThat(
            result.claims.claims["given_name"]
                ?.jsonPrimitive
                ?.content,
        ).isEqualTo("Ada")
    }

    @Test
    fun `a key binding addressed to us and to someone else is rejected`() {
        // RFC 9901 §4.3: aud MUST be a single string. A list naming us beside another
        // verifier was accepted as long as one entry matched.
        val mismatch =
            VerificationResult.Rejected(
                RejectionReason.AUDIENCE_MISMATCH,
                "key binding not addressed to this verifier",
            )
        assertThat(
            verifyPresentation(
                TestVectors.vector(kbAudiences = listOf("https://someone-else.example", TestVectors.AUDIENCE)),
            ),
        ).isEqualTo(mismatch)
        assertThat(
            verifyPresentation(
                TestVectors.vector(kbAudiences = listOf(TestVectors.AUDIENCE, "https://someone-else.example")),
            ),
        ).isEqualTo(mismatch)
        assertThat(verifyPresentation(TestVectors.vector(kbAudiences = emptyList()))).isEqualTo(mismatch)
    }

    @Test
    fun `a one-element audience array naming us is accepted, as the string would be`() {
        val compact = TestVectors.vector(kbAudiences = listOf(TestVectors.AUDIENCE))
        // Really an array on the wire, not flattened by the fixture.
        val payload = SignedJWT.parse(compact.substringAfterLast('~')).payload.toString()
        assertThat(payload).contains("\"aud\":[\"${TestVectors.AUDIENCE}\"]")
        assertThat(verifyPresentation(compact)).isInstanceOf(VerificationResult.Verified::class.java)
    }

    @Test
    fun `a key binding iat that wraps around in Nimbus is outside the window`() {
        // 18446745861278752 * 1000 overflows a long to NOW + 3600.384 s, and one hour is
        // still outside the window; 18446745861275152 lands on NOW + 0.384 s, which Nimbus
        // presented as fresh. Millisecond, negative and absurd values fail the same way.
        val outside =
            VerificationResult.Rejected(
                RejectionReason.INVALID_KEY_BINDING,
                "key binding iat outside the accepted window",
            )
        listOf(18_446_745_861_275_152L, Long.MAX_VALUE, Long.MIN_VALUE, -1L, TestVectors.NOW.toEpochMilli()).forEach {
            assertThat(
                verifyPresentation(TestVectors.vector(kbIssuedAtEpochSecond = it)),
            ).`as`(it.toString()).isEqualTo(outside)
        }
        assertThat(verifyPresentation(TestVectors.vector(kbIssuedAtEpochSecond = TestVectors.NOW.epochSecond)))
            .isInstanceOf(VerificationResult.Verified::class.java)
    }
}
