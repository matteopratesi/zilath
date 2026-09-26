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
package dev.zilath.verifier.openid4vp

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.CredentialStatus
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.TrustEvaluator
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Date

/**
 * The trust marks of the relying party's entity configuration. IT-Wallet 1.4.6 onboarding has
 * the relying party publish the trust marks the federation issued it; the entity
 * configuration had no place for them, so a wallet could not find the proof that the relying
 * party may ask for a credential.
 */
class RpTrustMarksTest {
    private val clock = Clock.fixed(Instant.parse("2026-09-26T08:00:00Z"), ZoneOffset.UTC)
    private val issuerKey = ECKeyGenerator(Curve.P_256).keyID("ta-marks").generate()
    private val federationKey = ECKeyGenerator(Curve.P_256).keyID("rp-fed").generate()

    private fun trustMark(
        type: String = VERIFIER_MARK,
        subject: String = ENTITY_ID,
    ): String =
        SignedJWT(
            JWSHeader
                .Builder(JWSAlgorithm.ES256)
                .keyID(issuerKey.keyID)
                .type(JOSEObjectType("trust-mark+jwt"))
                .build(),
            JWTClaimsSet
                .Builder()
                .issuer("https://ta.example")
                .subject(subject)
                .claim("trust_mark_type", type)
                .issueTime(Date.from(clock.instant()))
                .build(),
        ).apply { sign(ECDSASigner(issuerKey)) }.serialize()

    private fun federation(trustMarks: List<RpTrustMark> = emptyList()) =
        RpFederationConfig(
            entityId = ENTITY_ID,
            federationKey = federationKey,
            authorityHints = listOf("https://ta.example"),
            organizationName = "Teatro di Prova",
            contacts = listOf("biglietteria@teatro.example"),
            trustMarks = trustMarks,
        )

    private fun entityConfigurationOf(federation: RpFederationConfig): JWTClaimsSet {
        val config =
            RelyingPartyConfiguration(
                clientId = "openid_federation:$ENTITY_ID",
                endpoints = RpEndpoints("$ENTITY_ID/openid4vp/request", "$ENTITY_ID/openid4vp/response"),
                keys = RpKeys(requestSigningKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate()),
                trustEvaluator = TrustEvaluator { TrustDecision.Untrusted("unused") },
                statusChecker = StatusChecker { _, _ -> CredentialStatus.UNKNOWN },
                federation = federation,
            )
        return SignedJWT.parse(RpEntityConfiguration.build(config, federation, clock)).jwtClaimsSet
    }

    @Test
    fun `the trust marks issued to the relying party are published as OpenID Federation 1_0 lists them`() {
        val mark = trustMark()
        val claims = entityConfigurationOf(federation(listOf(RpTrustMark(VERIFIER_MARK, mark))))
        assertThat(claims.getListClaim("trust_marks"))
            .containsExactly(mapOf("trust_mark_type" to VERIFIER_MARK, "trust_mark" to mark))
    }

    @Test
    fun `without trust marks there is no trust_marks claim`() {
        assertThat(entityConfigurationOf(federation()).claims).doesNotContainKey("trust_marks")
    }

    @Test
    fun `a trust mark of another type, of another entity or no JWT at all is refused`() {
        // §3.1.2: the type in the entry MUST be the one in the trust mark; and a trust mark
        // issued to another entity proves nothing about this one.
        val refused =
            mapOf(
                "another type" to RpTrustMark(VERIFIER_MARK, trustMark(type = "https://ta.example/trust_marks/other")),
                "another entity" to RpTrustMark(VERIFIER_MARK, trustMark(subject = "https://other.example")),
                "no JWT" to RpTrustMark(VERIFIER_MARK, "not-a-jwt"),
                "no type" to RpTrustMark(" ", trustMark()),
            )
        for ((case, mark) in refused) {
            assertThatIllegalArgumentException().describedAs(case).isThrownBy { federation(listOf(mark)) }
        }
    }

    private companion object {
        const val ENTITY_ID = "https://rp.example"
        const val VERIFIER_MARK = "https://ta.example/trust_marks/federation-entity/openid_credential_verifier"
    }
}
