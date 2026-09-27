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
package dev.zilath.verifier.trust

import dev.zilath.verifier.core.CredentialStatus
import dev.zilath.verifier.core.IpzsFederationSnapshot
import dev.zilath.verifier.core.RawPresentation
import dev.zilath.verifier.core.RejectionReason
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TestVectors
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.VerificationContext
import dev.zilath.verifier.core.VerificationResult
import dev.zilath.verifier.trust.FederationFixtures.anchorStatementAboutLeaf
import dev.zilath.verifier.trust.FederationFixtures.chainEvaluator
import dev.zilath.verifier.trust.FederationFixtures.clock
import dev.zilath.verifier.trust.FederationFixtures.inputFor
import dev.zilath.verifier.trust.FederationFixtures.jwksClaim
import dev.zilath.verifier.trust.FederationFixtures.leafConfiguration
import dev.zilath.verifier.trust.FederationFixtures.sdJwtConfigurations
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * IT-Wallet 1.4.6 §6.12.1: the issuer must be allowed to issue the credential of interest.
 * A trusted leaf is trusted for the `vct`s its resolved metadata lists, and the verifier
 * refuses any other.
 */
class CredentialTypesTest {
    private val pidVct = "urn:eudi:pid:it:1"

    private fun issuerSection(vararg entries: Pair<String, Any?>) =
        mapOf("openid_credential_issuer" to mapOf("jwks" to jwksClaim(TestVectors.issuerEcKey)) + entries)

    private fun typesFor(chain: List<String>): Set<String>? {
        val decision = chainEvaluator().evaluate(inputFor(trustChain = chain))
        assertThat(decision).isInstanceOf(TrustDecision.Trusted::class.java)
        return (decision as TrustDecision.Trusted).credentialTypes
    }

    /** Presents the test vector (vct [TestVectors.VCT]) through the full verifier. */
    private fun present(chain: List<String>): VerificationResult {
        val context =
            VerificationContext(
                expectedNonce = TestVectors.NONCE,
                expectedAudiences = setOf(TestVectors.AUDIENCE),
                clock = clock,
                trustEvaluator = { input -> chainEvaluator().evaluate(input.copy(trustChain = chain)) },
                statusChecker = StatusChecker { _, _ -> CredentialStatus.VALID },
            )
        return SdJwtVcCredentialVerifier().verify(RawPresentation.SdJwtVcPresentation(TestVectors.vector()), context)
    }

    @Test
    fun `an issuer authorised for other types cannot issue this one`() {
        // The first probe of the review: the issuer lists only the PID, the anchor's policy
        // makes the section essential, and a credential of another type was Verified.
        val pidIssuer =
            listOf(
                leafConfiguration(
                    metadata = issuerSection("credential_configurations_supported" to sdJwtConfigurations(pidVct)),
                ),
                anchorStatementAboutLeaf {
                    claim(
                        "metadata_policy",
                        mapOf(
                            "openid_credential_issuer" to
                                mapOf("credential_configurations_supported" to mapOf("essential" to true)),
                        ),
                    )
                },
            )
        assertThat(typesFor(pidIssuer)).containsExactly(pidVct)
        val result = present(pidIssuer)
        assertThat(result).isInstanceOf(VerificationResult.Rejected::class.java)
        assertThat((result as VerificationResult.Rejected).reason).isEqualTo(RejectionReason.UNTRUSTED_ISSUER)
    }

    @Test
    fun `a member that only publishes signing keys is authorised for nothing`() {
        // The second probe: a leaf onboarded as a relying party that declares
        // openid_credential_issuer.jwks of its own, and no credential configuration.
        val relyingParty =
            listOf(
                leafConfiguration(
                    metadata =
                        issuerSection() +
                            mapOf("openid_credential_verifier" to mapOf("client_id" to FederationFixtures.LEAF_ID)),
                ),
                anchorStatementAboutLeaf {
                    claim(
                        "metadata_policy",
                        mapOf("openid_credential_verifier" to mapOf("client_id" to mapOf("essential" to true))),
                    )
                },
            )
        assertThat(typesFor(relyingParty)).isEmpty()
        assertThat(
            (present(relyingParty) as VerificationResult.Rejected).reason,
        ).isEqualTo(RejectionReason.UNTRUSTED_ISSUER)
    }

    @Test
    fun `an issuer listing the type presents it`() {
        val issuer = FederationFixtures.offlineChain()
        assertThat(typesFor(issuer)).containsExactly(TestVectors.VCT)
        assertThat(present(issuer)).isInstanceOf(VerificationResult.Verified::class.java)
    }

    @Test
    fun `only SD-JWT entries with a vct count`() {
        val configurations =
            mapOf(
                "current" to mapOf("format" to "dc+sd-jwt", "vct" to "urn:type:current"),
                "earlier" to mapOf("format" to "vc+sd-jwt", "vct" to "urn:type:earlier"),
                "mdoc" to mapOf("format" to "mso_mdoc", "doctype" to "org.iso.18013.5.1.mDL"),
                "other-format" to mapOf("format" to "jwt_vc_json", "vct" to "urn:type:jwt"),
                "no-vct" to mapOf("format" to "dc+sd-jwt"),
                "not-an-object" to "dc+sd-jwt",
            )
        val chain =
            listOf(
                leafConfiguration(metadata = issuerSection("credential_configurations_supported" to configurations)),
                FederationFixtures.anchorStatementAboutLeaf(),
            )
        assertThat(typesFor(chain)).containsExactlyInAnyOrder("urn:type:current", "urn:type:earlier")
        val malformed =
            listOf(
                leafConfiguration(metadata = issuerSection("credential_configurations_supported" to listOf(pidVct))),
                FederationFixtures.anchorStatementAboutLeaf(),
            )
        assertThat(typesFor(malformed)).isEmpty()
    }

    @Test
    fun `the types come from the resolved metadata, so a superior restricts them`() {
        val twoTypes =
            issuerSection(
                "credential_configurations_supported" to sdJwtConfigurations(pidVct, TestVectors.VCT),
            )
        // The superior's statement metadata replaces the section...
        val overlaid =
            listOf(
                leafConfiguration(metadata = twoTypes),
                anchorStatementAboutLeaf {
                    claim(
                        "metadata",
                        mapOf(
                            "openid_credential_issuer" to
                                mapOf("credential_configurations_supported" to sdJwtConfigurations(pidVct)),
                        ),
                    )
                },
            )
        assertThat(typesFor(overlaid)).containsExactly(pidVct)
        // ...and so does a policy forcing its value.
        val forced =
            listOf(
                leafConfiguration(metadata = twoTypes),
                anchorStatementAboutLeaf {
                    claim(
                        "metadata_policy",
                        mapOf(
                            "openid_credential_issuer" to
                                mapOf(
                                    "credential_configurations_supported" to
                                        mapOf("value" to sdJwtConfigurations(pidVct)),
                                ),
                        ),
                    )
                },
            )
        assertThat(typesFor(forced)).containsExactly(pidVct)
    }

    @Test
    fun `the production issuer is authorised for its SD-JWT types and the disability card among them`() {
        val anchor = TrustAnchorConfig(IpzsFederationSnapshot.TRUST_ANCHOR, IpzsFederationSnapshot.trustAnchorKeys.keys)
        val offline =
            FederationTrustEvaluator(
                anchor,
                FederationFixtures.unreachable,
                IpzsFederationSnapshot.clock,
                offlineFallback = true,
            )
        val decision =
            offline.evaluate(
                dev.zilath.verifier.core.IssuerTrustInput(
                    issuer = IpzsFederationSnapshot.CED_ISSUER,
                    keyId = null,
                    certificateChain = emptyList(),
                    trustChain = IpzsFederationSnapshot.cedIssuerChain,
                ),
            )
        val types = (decision as TrustDecision.Trusted).credentialTypes
        // Eight dc+sd-jwt configurations; the mso_mdoc one names no vct.
        assertThat(types).hasSize(8).contains(IpzsFederationSnapshot.CED_VCT)
    }
}
