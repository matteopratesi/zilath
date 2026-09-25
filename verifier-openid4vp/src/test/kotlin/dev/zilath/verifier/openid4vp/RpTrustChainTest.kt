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
import dev.zilath.verifier.core.TestVectors
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.junit.jupiter.api.Test
import java.time.Duration
import java.util.Date

/**
 * The request object's `trust_chain` header. It was a list fixed in configuration and sent
 * as it stood: after a day — what the statements of a real federation live — every request
 * object carried an expired chain.
 */
class RpTrustChainTest {
    private val clock = SteppingClock(TestVectors.NOW)
    private val entityId = "https://rp.example"
    private val anchor = "https://anchor.example"
    private val anchorKey = ECKeyGenerator(Curve.P_256).keyID("anchor").generate()
    private val federation =
        RpFederationConfig(
            entityId = entityId,
            federationKey = ECKeyGenerator(Curve.P_256).keyID("rp-fed").generate(),
            authorityHints = listOf(anchor),
            organizationName = "Teatro di Prova",
            contacts = listOf("biglietteria@teatro.example"),
        )
    private val config =
        RelyingPartyConfiguration(
            clientId = OPENID_FEDERATION_PREFIX + entityId,
            endpoints = RpEndpoints("$entityId/openid4vp/request", "$entityId/openid4vp/response"),
            keys = RpKeys(requestSigningKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate()),
            trustEvaluator = TestVectors.trustIssuerEc(),
            statusChecker = StatusChecker { _, _ -> CredentialStatus.VALID },
            federation = federation,
        )

    /** The RP's own entity configuration, then the anchor's statement about it, each living [validity]. */
    private fun chain(
        validity: Duration,
        subjectOfSuperior: String = entityId,
    ): List<String> {
        val leaf = RpEntityConfiguration.build(config, federation.copy(statementValidity = validity), clock)
        val statement =
            SignedJWT(
                JWSHeader
                    .Builder(JWSAlgorithm.ES256)
                    .keyID(anchorKey.keyID)
                    .type(JOSEObjectType(RpEntityConfiguration.ENTITY_STATEMENT_TYP))
                    .build(),
                JWTClaimsSet
                    .Builder()
                    .issuer(anchor)
                    .subject(subjectOfSuperior)
                    .issueTime(Date.from(clock.instant()))
                    .expirationTime(Date.from(clock.instant().plus(validity)))
                    .build(),
            ).apply { sign(ECDSASigner(anchorKey)) }
        return listOf(leaf, statement.serialize())
    }

    private fun headerOf(configuration: RelyingPartyConfiguration): Any? {
        val transaction =
            Transaction(
                id = TransactionId("tx-1"),
                nonce = "n".repeat(32),
                state = TransactionState.CREATED,
                createdAt = clock.instant(),
                expiresAt = clock.instant().plusSeconds(300),
                request = PresentationRequest.forTestPid("urn:eudi:pid:it:1"),
                pollTokenHash = "hash",
                responseEncryptionKey = newTransactionEncryptionKey(),
            )
        return SignedJWT
            .parse(
                buildRequestJwt(configuration, transaction, clock.instant()),
            ).header
            .getCustomParam("trust_chain")
    }

    @Test
    fun `a chain travels in the request object until it expires, then no longer`() {
        val chain = chain(validity = Duration.ofHours(1))
        val withChain = config.copy(federation = federation.copy(trustChain = chain))
        assertThat(headerOf(withChain)).isEqualTo(chain)
        assertThat(headerOf(config)).isNull()
        // Within a minute of its earliest exp the chain could reach the wallet expired.
        clock.advance(Duration.ofMinutes(59).plusSeconds(1))
        assertThat(headerOf(withChain)).isNull()
        clock.advance(Duration.ofHours(1))
        assertThat(headerOf(withChain)).isNull()
    }

    @Test
    fun `a chain source is asked for every request object`() {
        var current = chain(validity = Duration.ofHours(1))
        val renewing = config.copy(federation = federation.copy(trustChainSource = { current }))
        assertThat(headerOf(renewing)).isEqualTo(current)
        clock.advance(Duration.ofHours(2))
        assertThat(headerOf(renewing)).isNull()
        current = chain(validity = Duration.ofHours(1))
        assertThat(headerOf(renewing)).isEqualTo(current)
        // A failing or ill-shaped source costs the header, never the request object.
        val broken = config.copy(federation = federation.copy(trustChainSource = { error("federation unreachable") }))
        assertThat(headerOf(broken)).isNull()
        val foreign = config.copy(federation = federation.copy(trustChainSource = { listOf("not-a-jwt") }))
        assertThat(headerOf(foreign)).isNull()
    }

    @Test
    fun `a chain that is not this RP's is refused at construction`() {
        // Not a JWT, not entity statements, not starting with our own configuration, not
        // linked by iss and sub: each would be sent to every wallet and fail there.
        assertThatIllegalArgumentException().isThrownBy { federation.copy(trustChain = listOf("eyJa.leaf.sig")) }
        val valid = chain(validity = Duration.ofHours(1))
        assertThatIllegalArgumentException().isThrownBy { federation.copy(trustChain = valid.reversed()) }
        assertThatIllegalArgumentException()
            .isThrownBy {
                federation.copy(
                    trustChain = chain(Duration.ofHours(1), subjectOfSuperior = "https://other.example"),
                )
            }.withMessageContaining("linked")
        assertThatIllegalArgumentException()
            .isThrownBy { federation.copy(entityId = "https://elsewhere.example", trustChain = valid) }
            .withMessageContaining("own entity configuration")
        assertThatIllegalArgumentException()
            .isThrownBy { federation.copy(trustChain = valid, trustChainSource = { valid }) }
        // An expired chain is no configuration error: the RP still serves, without the header.
        clock.advance(Duration.ofHours(3))
        assertThat(federation.copy(trustChain = valid).trustChain).isEqualTo(valid)
    }
}
