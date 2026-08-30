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
        status: StatusChecker = StatusChecker { _, _ -> CredentialStatus.VALID },
        expectedVcts: Set<String> = emptySet(),
    ) = VerificationContext(
        expectedNonce = nonce,
        expectedAudiences = setOf(audience),
        expectedVcts = expectedVcts,
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
    fun `temporal checks tolerate a minute of issuer clock drift`() {
        // The same tolerance the status list checker and the trust chain walk apply: a
        // credential expired thirty seconds "ago", or valid in thirty seconds, is someone
        // else's NTP drift, not a forgery. The two tests above pin that beyond the minute
        // both checks still bite.
        assertThat(verify(TestVectors.vector(exp = TestVectors.NOW.minusSeconds(30))))
            .isInstanceOf(VerificationResult.Verified::class.java)
        assertThat(verify(TestVectors.vector(nbf = TestVectors.NOW.plusSeconds(30))))
            .isInstanceOf(VerificationResult.Verified::class.java)
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
        val result = verify(compact, context(status = StatusChecker { _, _ -> CredentialStatus.REVOKED }))
        assertThat(rejectionOf(result)).isEqualTo(RejectionReason.REVOKED)
    }

    @Test
    fun `unknown status is rejected as status check failure`() {
        val compact = TestVectors.vector(statusUri = "https://status.example/1", statusIndex = 3)
        val result = verify(compact, context(status = StatusChecker { _, _ -> CredentialStatus.UNKNOWN }))
        assertThat(rejectionOf(result)).isEqualTo(RejectionReason.STATUS_CHECK_FAILED)
    }

    @Test
    fun `credential with status is verified when the list says valid`() {
        val compact = TestVectors.vector(statusUri = "https://status.example/1", statusIndex = 3)
        val checked = mutableListOf<StatusReference>()
        val trustSeen = mutableListOf<StatusIssuerTrust>()
        val result =
            verify(
                compact,
                context(status = { ref, trust ->
                    checked.add(ref)
                    trustSeen.add(trust)
                    CredentialStatus.VALID
                }),
            )
        assertThat(result).isInstanceOf(VerificationResult.Verified::class.java)
        assertThat(checked).containsExactly(StatusReference("https://status.example/1", 3))
        // The checker is only as good as what it is handed: assert the verifier actually
        // propagates the issuer and the keys it trusted, rather than something empty that
        // a checker ignoring its second argument would never notice.
        assertThat(trustSeen).hasSize(1)
        assertThat(trustSeen.single().issuer).isEqualTo(TestVectors.ISSUER)
        assertThat(trustSeen.single().issuerKeys).isNotEmpty()
    }

    @Test
    fun `the outcome carries no stable per-credential identifier`() {
        // cnf.jwk is the holder's public key and status.status_list.idx is this credential's
        // slot in its issuer's revocation list. Both are the same on every presentation of
        // the same credential, so handing them to the application would let two checkouts —
        // different venues, months apart — be linked to one person. They exist for
        // verification and the library is done with them by the time it answers.
        val compact = TestVectors.vector(statusUri = "https://status.example/1", statusIndex = 3)
        val result = verify(compact, context(status = { _, _ -> CredentialStatus.VALID }))
        val claims = (result as VerificationResult.Verified).claims.claims
        assertThat(claims).doesNotContainKey("cnf")
        assertThat(claims).doesNotContainKey("status")
        // What was actually asked for is still there.
        assertThat(claims).containsKeys("entitled", "given_name", "vct")
    }

    @Test
    fun `a credential of a type that was not requested is rejected`() {
        // The wallet chooses what to present. Without this check "verified" would only mean
        // "some credential this issuer signed", not "the credential you asked for".
        val other = TestVectors.vector(vct = "urn:zilath:test:something-else")
        val result = verify(other, context(expectedVcts = setOf(TestVectors.VCT)))
        assertThat(rejectionOf(result)).isEqualTo(RejectionReason.UNSUPPORTED_FORMAT)

        val right = TestVectors.vector()
        assertThat(verify(right, context(expectedVcts = setOf(TestVectors.VCT))))
            .isInstanceOf(VerificationResult.Verified::class.java)
    }

    @Test
    fun `a status claim that is not an object fails closed instead of skipping revocation`() {
        // The sibling case — an object with a malformed status_list — already rejects. This
        // one used to be swallowed, which skipped the revocation check altogether: the
        // quietest way to make a revoked credential look fine.
        val compact = TestVectors.vector(statusNotAnObject = true)
        val result = verify(compact, context(status = { _, _ -> CredentialStatus.REVOKED }))
        assertThat(rejectionOf(result)).isEqualTo(RejectionReason.STATUS_CHECK_FAILED)
    }

    @Test
    fun `mdoc presentations are not supported in v0`() {
        val result = verifier.verify(RawPresentation.MdocPresentation("AAAA"), context())
        assertThat(rejectionOf(result)).isEqualTo(RejectionReason.UNSUPPORTED_FORMAT)
    }
}
