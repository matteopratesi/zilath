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

import dev.zilath.verifier.core.IpzsFederationSnapshot
import dev.zilath.verifier.core.IssuerTrustInput
import dev.zilath.verifier.core.TrustDecision
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * The production IT-Wallet federation, exactly as it was served on 2026-09-24, must stay
 * trusted: these are the documents a relying party anchored to `ta.wallet.ipzs.it` reads
 * for every European Disability Card, and a library that turns them into Untrusted turns
 * away every genuine holder. The synthetic fixtures could not see that — they were written
 * by the same hands as the code — so every change to chain validation runs against these.
 */
class IpzsProductionChainTest {
    private val anchor =
        TrustAnchorConfig(IpzsFederationSnapshot.TRUST_ANCHOR, IpzsFederationSnapshot.trustAnchorKeys.keys)

    private val fetched = mutableListOf<String>()

    /** Serves the frozen documents and records every URL the evaluator asks for. */
    private val recordingFetcher =
        FederationFetcher { url ->
            fetched += url
            IpzsFederationSnapshot.servedDocuments[url] ?: error("not a frozen document")
        }

    private fun input(trustChain: List<String> = emptyList()) =
        IssuerTrustInput(
            issuer = IpzsFederationSnapshot.CED_ISSUER,
            keyId = null,
            certificateChain = emptyList(),
            trustChain = trustChain,
        )

    private fun assertTrustedForTheRealIssuerKey(decision: TrustDecision) {
        assertThat(decision).isInstanceOf(TrustDecision.Trusted::class.java)
        val trusted = decision as TrustDecision.Trusted
        assertThat(trusted.issuerKeys.map { it.keyID }).containsExactly(IpzsFederationSnapshot.CED_ISSUER_SIGNING_KID)
    }

    @Test
    fun `the production chain resolved online is trusted for the issuer's real signing key`() {
        val decision =
            FederationTrustEvaluator(anchor, recordingFetcher, IpzsFederationSnapshot.clock).evaluate(input())

        assertTrustedForTheRealIssuerKey(decision)
        // Exactly the three documents production would read, each once, and nothing else.
        assertThat(fetched).containsExactlyInAnyOrderElementsOf(IpzsFederationSnapshot.servedDocuments.keys)
    }

    @Test
    fun `the production chain carried as a trust_chain header is trusted for the same key`() {
        val decision =
            FederationTrustEvaluator(anchor, recordingFetcher, IpzsFederationSnapshot.clock)
                .evaluate(input(trustChain = IpzsFederationSnapshot.cedIssuerChain))

        assertTrustedForTheRealIssuerKey(decision)
        assertThat(fetched).allMatch { it in IpzsFederationSnapshot.servedDocuments }
    }
}
