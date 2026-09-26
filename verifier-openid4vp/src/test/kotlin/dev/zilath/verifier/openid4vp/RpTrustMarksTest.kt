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
import java.time.Duration
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

    @Suppress("LongParameterList") // test factory: every parameter is one field a wallet checks
    private fun trustMark(
        type: String = VERIFIER_MARK,
        subject: String = ENTITY_ID,
        typ: String? = "trust-mark+jwt",
        kid: String? = issuerKey.keyID,
        issuer: String? = "https://ta.example",
        issuedAt: Instant? = clock.instant(),
        expiresAt: Instant? = clock.instant().plus(Duration.ofDays(365)),
    ): String =
        SignedJWT(
            JWSHeader
                .Builder(JWSAlgorithm.ES256)
                .apply { if (kid != null) keyID(kid) }
                .apply { if (typ != null) type(JOSEObjectType(typ)) }
                .build(),
            JWTClaimsSet
                .Builder()
                .issuer(issuer)
                .subject(subject)
                .claim("trust_mark_type", type)
                .issueTime(issuedAt?.let(Date::from))
                .expirationTime(expiresAt?.let(Date::from))
                .build(),
        ).apply { sign(ECDSASigner(issuerKey)) }.serialize()

    private fun federation(
        trustMarks: List<RpTrustMark> = emptyList(),
        source: TrustMarkSource? = null,
    ) = RpFederationConfig(
        entityId = ENTITY_ID,
        federationKey = federationKey,
        authorityHints = listOf("https://ta.example"),
        organizationName = "Teatro di Prova",
        contacts = listOf("biglietteria@teatro.example"),
        trustMarks = trustMarks,
        trustMarkSource = source,
    )

    private fun entityConfigurationOf(
        federation: RpFederationConfig,
        at: Clock = clock,
    ): JWTClaimsSet {
        val config =
            RelyingPartyConfiguration(
                clientId = "openid_federation:$ENTITY_ID",
                endpoints = RpEndpoints("$ENTITY_ID/openid4vp/request", "$ENTITY_ID/openid4vp/response"),
                keys = RpKeys(requestSigningKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate()),
                trustEvaluator = TrustEvaluator { TrustDecision.Untrusted("unused") },
                statusChecker = StatusChecker { _, _ -> CredentialStatus.UNKNOWN },
                federation = federation,
            )
        return SignedJWT.parse(RpEntityConfiguration.build(config, federation, at)).jwtClaimsSet
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
    fun `a trust mark a wallet would reject is refused at construction`() {
        // §3.1.2: the type in the entry MUST be the one in the trust mark, and one issued to
        // another entity proves nothing about this one. §7.1 and §7.3: typed trust-mark+jwt,
        // with a kid, an iss and an iat; IT-Wallet 1.4.6 table 8.7 also requires exp.
        val refused =
            mapOf(
                "another type" to trustMark(type = "https://ta.example/trust_marks/other"),
                "another entity" to trustMark(subject = "https://other.example"),
                "untyped" to trustMark(typ = null),
                "typed as something else" to trustMark(typ = "entity-statement+jwt"),
                "no kid" to trustMark(kid = null),
                "no iss" to trustMark(issuer = null),
                "no iat" to trustMark(issuedAt = null),
                "no exp" to trustMark(expiresAt = null),
                "no JWT" to "not-a-jwt",
            ).mapValues { (_, jwt) -> RpTrustMark(VERIFIER_MARK, jwt) } +
                ("no type" to RpTrustMark(" ", trustMark()))
        for ((case, mark) in refused) {
            assertThatIllegalArgumentException().describedAs(case).isThrownBy { federation(listOf(mark)) }
        }
    }

    @Test
    fun `a trust mark is no longer published once it has expired`() {
        // A wallet must reject an expired mark; the relying party kept publishing it.
        val expiring = RpTrustMark(VERIFIER_MARK, trustMark(expiresAt = clock.instant().plus(Duration.ofDays(1))))
        val federation = federation(listOf(expiring))
        assertThat(entityConfigurationOf(federation).getListClaim("trust_marks")).hasSize(1)
        val later = Clock.offset(clock, Duration.ofDays(1))
        assertThat(entityConfigurationOf(federation, later).claims).doesNotContainKey("trust_marks")
    }

    @Test
    fun `a trust mark source renews the marks, and what it gives is checked as configured ones are`() {
        val fresh = RpTrustMark(VERIFIER_MARK, trustMark())
        val expired = RpTrustMark(VERIFIER_MARK, trustMark(expiresAt = clock.instant().minusSeconds(1)))
        val foreign = RpTrustMark(VERIFIER_MARK, trustMark(subject = "https://other.example"))
        val claims = entityConfigurationOf(federation(source = { listOf(fresh, expired, foreign) }))
        assertThat(claims.getListClaim("trust_marks"))
            .containsExactly(mapOf("trust_mark_type" to VERIFIER_MARK, "trust_mark" to fresh.jwt))
        // A source that fails publishes nothing rather than failing the entity configuration.
        assertThat(
            entityConfigurationOf(federation(source = { error("down") })).claims,
        ).doesNotContainKey("trust_marks")
        assertThatIllegalArgumentException().isThrownBy { federation(listOf(fresh), source = { listOf(fresh) }) }
    }

    private companion object {
        const val ENTITY_ID = "https://rp.example"
        const val VERIFIER_MARK = "https://ta.example/trust_marks/federation-entity/openid_credential_verifier"
    }
}
