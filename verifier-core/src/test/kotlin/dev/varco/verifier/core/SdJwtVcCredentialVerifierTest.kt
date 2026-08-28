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
package dev.varco.verifier.core

import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonPrimitive
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.ZoneOffset

class SdJwtVcCredentialVerifierTest {
    private val verifier = SdJwtVcCredentialVerifier()
    private val clock = Clock.fixed(TestVectors.NOW, ZoneOffset.UTC)

    private fun context(
        nonce: String = TestVectors.NONCE,
        audience: String = TestVectors.AUDIENCE,
        trust: TrustEvaluator = TestVectors.trustIssuerEc(),
        status: StatusChecker = StatusChecker { CredentialStatus.VALID },
    ) = VerificationContext(
        expectedNonce = nonce,
        expectedAudiences = setOf(audience),
        clock = clock,
        trustEvaluator = trust,
        statusChecker = status,
    )

    private fun verify(
        compact: String,
        ctx: VerificationContext = context(),
    ): VerificationResult = verifier.verify(RawPresentation.SdJwtVcPresentation(compact), ctx)

    private fun rejectionOf(result: VerificationResult): RejectionReason {
        assertThat(result).isInstanceOf(VerificationResult.Rejected::class.java)
        return (result as VerificationResult.Rejected).reason
    }

    @Test
    fun `valid presentation is verified with disclosed claims`() {
        val result = verify(TestVectors.vector())
        assertThat(result).isInstanceOf(VerificationResult.Verified::class.java)
        val claims = (result as VerificationResult.Verified).claims.claims
        assertThat(claims["given_name"]?.jsonPrimitive?.content).isEqualTo("Ada")
        assertThat(claims["family_name"]?.jsonPrimitive?.content).isEqualTo("Lovelace")
        assertThat(claims["entitled"]?.jsonPrimitive?.boolean).isTrue()
        assertThat(claims.keys).doesNotContain("_sd")
    }

    @Test
    fun `valid presentation with RSA issuer is verified`() {
        val result = verify(TestVectors.vector(useRsaIssuer = true), context(trust = TestVectors.trustIssuerRsa()))
        assertThat(result).isInstanceOf(VerificationResult.Verified::class.java)
    }

    @Test
    fun `a mixed trust list verifies even when the first key type does not match`() {
        // Regression: an EC verifier throwing on an RS256 JWT must not abort the key loop.
        val mixedTrust =
            TrustEvaluator {
                TrustDecision.Trusted(
                    listOf(TestVectors.issuerEcKey.toPublicJWK(), TestVectors.issuerRsaKey.toPublicJWK()),
                )
            }
        val result = verify(TestVectors.vector(useRsaIssuer = true), context(trust = mixedTrust))
        assertThat(result).isInstanceOf(VerificationResult.Verified::class.java)
    }

    @Test
    fun `tampered issuer signature is rejected`() {
        val compact = TestVectors.withTamperedIssuerSignature(TestVectors.vector())
        assertThat(rejectionOf(verify(compact))).isEqualTo(RejectionReason.INVALID_ISSUER_SIGNATURE)
    }

    @Test
    fun `tampered disclosure is rejected`() {
        val compact = TestVectors.withTamperedDisclosure(TestVectors.vector())
        assertThat(rejectionOf(verify(compact))).isEqualTo(RejectionReason.DISCLOSURE_TAMPERED)
    }

    @Test
    fun `tampered key binding signature is rejected`() {
        val compact = TestVectors.withTamperedKeyBindingSignature(TestVectors.vector())
        assertThat(rejectionOf(verify(compact))).isEqualTo(RejectionReason.INVALID_KEY_BINDING)
    }

    @Test
    fun `nonce mismatch is rejected`() {
        val result = verify(TestVectors.vector(), context(nonce = "another-nonce"))
        assertThat(rejectionOf(result)).isEqualTo(RejectionReason.NONCE_MISMATCH)
    }

    @Test
    fun `audience mismatch is rejected`() {
        val result = verify(TestVectors.vector(), context(audience = "https://someone-else.example"))
        assertThat(rejectionOf(result)).isEqualTo(RejectionReason.AUDIENCE_MISMATCH)
    }

    @Test
    fun `expired credential is rejected`() {
        val compact = TestVectors.vector(exp = TestVectors.NOW.minusSeconds(60))
        assertThat(rejectionOf(verify(compact))).isEqualTo(RejectionReason.EXPIRED)
    }

    @Test
    fun `credential not yet valid is rejected`() {
        val compact = TestVectors.vector(nbf = TestVectors.NOW.plusSeconds(600))
        assertThat(rejectionOf(verify(compact))).isEqualTo(RejectionReason.NOT_YET_VALID)
    }

    @Test
    fun `stale key binding is rejected`() {
        val compact = TestVectors.vector(kbIssuedAt = TestVectors.NOW.minusSeconds(3600))
        assertThat(rejectionOf(verify(compact))).isEqualTo(RejectionReason.INVALID_KEY_BINDING)
    }

    @Test
    fun `missing holder key is rejected`() {
        val compact = TestVectors.vector(includeCnf = false)
        assertThat(rejectionOf(verify(compact))).isEqualTo(RejectionReason.INVALID_KEY_BINDING)
    }

    @Test
    fun `untrusted issuer is rejected before any signature check`() {
        val distrustAll = TrustEvaluator { TrustDecision.Untrusted("not in the federation") }
        val result = verify(TestVectors.vector(), context(trust = distrustAll))
        assertThat(rejectionOf(result)).isEqualTo(RejectionReason.UNTRUSTED_ISSUER)
    }

    @Test
    fun `trusted decision without keys is rejected`() {
        val noKeys = TrustEvaluator { TrustDecision.Trusted(emptyList()) }
        val result = verify(TestVectors.vector(), context(trust = noKeys))
        assertThat(rejectionOf(result)).isEqualTo(RejectionReason.UNTRUSTED_ISSUER)
    }

    @Test
    fun `garbage input is rejected as malformed`() {
        assertThat(rejectionOf(verify("this-is-not-an-sd-jwt"))).isEqualTo(RejectionReason.MALFORMED)
    }

    @Test
    fun `revoked credential is rejected`() {
        val compact = TestVectors.vector(statusUri = "https://status.example/1", statusIndex = 3)
        val result = verify(compact, context(status = StatusChecker { CredentialStatus.REVOKED }))
        assertThat(rejectionOf(result)).isEqualTo(RejectionReason.REVOKED)
    }

    @Test
    fun `unknown status is rejected as status check failure`() {
        val compact = TestVectors.vector(statusUri = "https://status.example/1", statusIndex = 3)
        val result = verify(compact, context(status = StatusChecker { CredentialStatus.UNKNOWN }))
        assertThat(rejectionOf(result)).isEqualTo(RejectionReason.STATUS_CHECK_FAILED)
    }

    @Test
    fun `credential with status is verified when the list says valid`() {
        val compact = TestVectors.vector(statusUri = "https://status.example/1", statusIndex = 3)
        val checked = mutableListOf<StatusReference>()
        val result =
            verify(
                compact,
                context(status = { ref ->
                    checked.add(ref)
                    CredentialStatus.VALID
                }),
            )
        assertThat(result).isInstanceOf(VerificationResult.Verified::class.java)
        assertThat(checked).containsExactly(StatusReference("https://status.example/1", 3))
    }

    @Test
    fun `mdoc presentations are not supported in v0`() {
        val result = verifier.verify(RawPresentation.MdocPresentation("AAAA"), context())
        assertThat(rejectionOf(result)).isEqualTo(RejectionReason.UNSUPPORTED_FORMAT)
    }
}
