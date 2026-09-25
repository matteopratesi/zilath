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

import com.nimbusds.jose.Header
import com.nimbusds.jose.util.Base64URL
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

/**
 * What a presentation may be made of before and after its signatures: size, count and
 * nesting limits checked before anything is parsed, the Nimbus header limit named for what
 * it is, and disclosure shapes the EUDI library throws on or lets through.
 */
class InputRobustnessTest {
    /** A trust evaluator that counts its calls: zero proves a rejection came before any parsing. */
    private class CountingTrust : TrustEvaluator {
        var calls = 0

        override fun evaluate(issuerChain: IssuerTrustInput): TrustDecision {
            calls++
            return TrustDecision.Trusted(listOf(TestVectors.issuerEcKey.toPublicJWK()))
        }
    }

    private fun malformed(detail: String) = VerificationResult.Rejected(RejectionReason.MALFORMED, detail)

    private fun tampered(detail: String) = VerificationResult.Rejected(RejectionReason.DISCLOSURE_TAMPERED, detail)

    /** [compact] with [disclosures] inserted right after the issuer JWT. */
    private fun withExtraDisclosures(
        compact: String,
        disclosures: List<String>,
    ): String = compact.replaceFirst("~", "~" + disclosures.joinToString("") { "$it~" })

    private fun nested(depth: Int) = "[".repeat(depth) + "]".repeat(depth)

    // --- limits checked before parsing ----------------------------------------------------

    @Test
    fun `a presentation over the size limit is refused before anything is parsed`() {
        val trust = CountingTrust()
        val oversized =
            withExtraDisclosures(TestVectors.vector(), listOf("A".repeat(PresentationLimits.DEFAULT_MAX_LENGTH)))
        assertThat(verifyPresentation(oversized, testContext(trust = trust)))
            .isEqualTo(malformed("presentation exceeds the size limit"))
        val small = testContext(trust = trust).copy(presentationLimits = PresentationLimits(maxLength = 100))
        assertThat(
            verifyPresentation(TestVectors.vector(), small),
        ).isEqualTo(malformed("presentation exceeds the size limit"))
        assertThat(trust.calls).isZero()
        assertThat(verifyPresentation(TestVectors.vector(), testContext(trust = trust)))
            .isInstanceOf(VerificationResult.Verified::class.java)
    }

    @Test
    fun `a presentation with too many disclosures is refused before anything is parsed`() {
        val trust = CountingTrust()
        val decoy = TestVectors.encodeDisclosure("""["c2FsdA","decoy",1]""")
        val atLimit = PresentationLimits.DEFAULT_MAX_DISCLOSURES - 3 // the vector discloses three claims
        assertThat(
            verifyPresentation(
                withExtraDisclosures(
                    TestVectors.vector(),
                    List(atLimit + 1) {
                        decoy
                    },
                ),
                testContext(trust = trust),
            ),
        ).isEqualTo(malformed("presentation has too many disclosures"))
        assertThat(trust.calls).isZero()
        // At the limit the count passes, and the unreferenced decoys fail where they always did.
        assertThat(
            verifyPresentation(
                withExtraDisclosures(
                    TestVectors.vector(),
                    List(atLimit) {
                        decoy
                    },
                ),
                testContext(trust = trust),
            ),
        ).isEqualTo(tampered("disclosures do not match the credential"))
        assertThat(trust.calls).isOne()
    }

    @Test
    fun `a deeply nested disclosure is refused before the json parser sees it`() {
        // Unreferenced: the EUDI library would reject it, after parsing all of it.
        val trust = CountingTrust()
        val deep = TestVectors.encodeDisclosure("""["c2FsdA","deep",${nested(10_000)}]""")
        assertThat(
            verifyPresentation(withExtraDisclosures(TestVectors.vector(), listOf(deep)), testContext(trust = trust)),
        ).isEqualTo(malformed("a disclosure is nested too deeply"))
        assertThat(trust.calls).isZero()
    }

    @Test
    fun `a deeply nested disclosure the issuer signed is refused, not thrown`() {
        // Referenced from _sd: this is the shape that exhausted the heap or the stack
        // inside verify() in the fourth internal review.
        val signed = TestVectors.handMade(disclosures = listOf("""["c2FsdA","deep",${nested(5_000)}]"""))
        assertThat(verifyPresentation(signed)).isEqualTo(malformed("a disclosure is nested too deeply"))
    }

    @Test
    fun `the depth limit counts the disclosure's own array and bites exactly past it`() {
        val limit = PresentationLimits.DEFAULT_MAX_DISCLOSURE_DEPTH
        val atLimit = TestVectors.handMade(disclosures = listOf("""["c2FsdA","nested",${nested(limit - 1)}]"""))
        val result = verifyPresentation(atLimit) as VerificationResult.Verified
        assertThat(result.claims.claims["nested"]?.jsonArray).isNotNull()
        val overLimit = TestVectors.handMade(disclosures = listOf("""["c2FsdA","nested",${nested(limit)}]"""))
        assertThat(verifyPresentation(overLimit)).isEqualTo(malformed("a disclosure is nested too deeply"))
    }

    @Test
    fun `brackets inside json strings do not count as nesting`() {
        val text = "[".repeat(100) + "{\\\"" + "]".repeat(100)
        val compact = TestVectors.handMade(disclosures = listOf("""["c2FsdA","text","$text"]"""))
        val result = verifyPresentation(compact) as VerificationResult.Verified
        assertThat(
            result.claims.claims["text"]
                ?.jsonPrimitive
                ?.content,
        ).startsWith("[[[[").endsWith("]]]]")
    }

    @Test
    fun `a disclosure that is not base64url is tampered, as the library would say`() {
        val trust = CountingTrust()
        val compact = withExtraDisclosures(TestVectors.vector(), listOf("not+base64/url="))
        assertThat(verifyPresentation(compact, testContext(trust = trust)))
            .isEqualTo(tampered("disclosures do not match the credential"))
        assertThat(trust.calls).isZero()
    }

    @Test
    fun `limits are validated at construction`() {
        assertThatThrownBy { PresentationLimits(maxLength = 0) }.isInstanceOf(IllegalArgumentException::class.java)
        assertThatThrownBy {
            PresentationLimits(
                maxDisclosures = -1,
            )
        }.isInstanceOf(IllegalArgumentException::class.java)
        assertThatThrownBy {
            PresentationLimits(
                maxDisclosureDepth = 0,
            )
        }.isInstanceOf(IllegalArgumentException::class.java)
    }

    // --- the Nimbus header limit ----------------------------------------------------------

    @Test
    fun `the production issuer's trust chain does not fit a JOSE header, and says so`() {
        // IT-Wallet 1.4.6 lets an issuer embed trust_chain in the credential header. The real
        // disability card issuer's entity configuration alone is 39,668 characters, twice
        // what Nimbus parses; the credential used to come back as "does not parse".
        val trust = CountingTrust()
        val chain = IpzsFederationSnapshot.cedIssuerChain
        val compact = TestVectors.vector(issuerHeaderParams = mapOf("trust_chain" to chain))
        assertThat(verifyPresentation(compact, testContext(trust = trust)))
            .isEqualTo(malformed("issuer JWT header exceeds the parser limit"))
        assertThat(trust.calls).isZero()
    }

    @Test
    fun `a trust chain that fits the header still verifies`() {
        // The anchor's own configuration and its statement about the issuer: 12,355
        // characters of real documents.
        val chain =
            listOf(
                IpzsFederationSnapshot.statementAboutCedIssuer,
                IpzsFederationSnapshot.trustAnchorEntityConfiguration,
            )
        val compact = TestVectors.vector(issuerHeaderParams = mapOf("trust_chain" to chain))
        assertThat(verifyPresentation(compact)).isInstanceOf(VerificationResult.Verified::class.java)
    }

    @Test
    fun `the header limit is exactly the one Nimbus applies`() {
        val base = headerLength(TestVectors.vector(issuerHeaderParams = mapOf("pad" to "")))
        val padding = Header.MAX_HEADER_STRING_LENGTH - base
        val atLimit = TestVectors.vector(issuerHeaderParams = mapOf("pad" to "x".repeat(padding)))
        assertThat(headerLength(atLimit)).isEqualTo(Header.MAX_HEADER_STRING_LENGTH)
        assertThat(verifyPresentation(atLimit)).isInstanceOf(VerificationResult.Verified::class.java)
        val overLimit = TestVectors.vector(issuerHeaderParams = mapOf("pad" to "x".repeat(padding + 1)))
        assertThat(verifyPresentation(overLimit)).isEqualTo(malformed("issuer JWT header exceeds the parser limit"))
    }

    private fun headerLength(compact: String): Int = Base64URL(compact.substringBefore('.')).decodeToString().length

    // --- disclosures the library throws on, or lets through -------------------------------

    @Test
    fun `an _sd that is not an array is rejected, not thrown`() {
        assertThat(verifyPresentation(TestVectors.handMade(mapOf("_sd" to 5))))
            .isEqualTo(tampered("disclosures cannot be applied to the credential"))
    }

    @Test
    fun `a disclosure colliding with a plaintext claim is rejected, not thrown`() {
        val compact =
            TestVectors.handMade(
                mapOf("given_name" to "Eve"),
                disclosures = listOf("""["c2FsdA","given_name","Ada"]"""),
            )
        assertThat(verifyPresentation(compact)).isEqualTo(tampered("disclosures cannot be applied to the credential"))
    }

    @Test
    fun `an array element disclosure referenced from _sd is rejected, not thrown`() {
        val compact = TestVectors.handMade(disclosures = listOf("""["c2FsdA","Ada"]"""))
        assertThat(verifyPresentation(compact)).isEqualTo(tampered("disclosures cannot be applied to the credential"))
    }

    @Test
    fun `a disclosure naming a reserved or non-string claim is rejected`() {
        // RFC 9901 §4.2.1 / §7.1: the name MUST be a string other than _sd and "...".
        listOf(
            """["c2FsdA","...","QUJD"]""",
            """["c2FsdA","_sd",[]]""",
            """["c2FsdA",5,true]""",
            """["c2FsdA",null,true]""",
            """["c2FsdA",true,1]""",
        ).forEach {
            assertThat(verifyPresentation(TestVectors.handMade(disclosures = listOf(it))))
                .`as`(it)
                .isEqualTo(tampered("a disclosure does not name a valid claim"))
        }
        // An object as the name the library already refuses to read at all.
        val objectName = verifyPresentation(TestVectors.handMade(disclosures = listOf("""["c2FsdA",{"a":1},1]""")))
        assertThat((objectName as VerificationResult.Rejected).reason).isEqualTo(RejectionReason.DISCLOSURE_TAMPERED)
    }

    @Test
    fun `a reserved name is rejected at any depth`() {
        val inner = TestVectors.encodeDisclosure("""["c2FsdA","...","x"]""")
        val compact =
            TestVectors.handMade(
                payload = mapOf("address" to mapOf("_sd" to listOf(TestVectors.digestOf(inner)))),
                disclosures = listOf("""["c2FsdA","...","x"]"""),
                referenced = false,
            )
        assertThat(verifyPresentation(compact)).isEqualTo(tampered("a disclosure does not name a valid claim"))
    }

    @Test
    fun `an ordinary hand-made disclosure verifies`() {
        val compact = TestVectors.handMade(disclosures = listOf("""["c2FsdA","given_name","Ada"]"""))
        val result = verifyPresentation(compact) as VerificationResult.Verified
        assertThat(
            result.claims.claims["given_name"]
                ?.jsonPrimitive
                ?.content,
        ).isEqualTo("Ada")
    }
}
