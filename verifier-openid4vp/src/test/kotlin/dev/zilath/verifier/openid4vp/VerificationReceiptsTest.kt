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

import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.CredentialStatus
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TestVectors
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.ZoneOffset

class VerificationReceiptsTest {
    private val signingKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate()
    private val config =
        RelyingPartyConfiguration(
            clientId = TestVectors.AUDIENCE,
            endpoints = RpEndpoints("https://rp.example/req", "https://rp.example/res"),
            keys =
                RpKeys(
                    requestSigningKey = signingKey,
                    responseEncryptionKey = ECKeyGenerator(Curve.P_256).keyID("rp-enc").generate(),
                ),
            trustEvaluator = TestVectors.trustIssuerEc(),
            statusChecker = StatusChecker { CredentialStatus.VALID },
        )
    private val receipts = VerificationReceipts(config, Clock.fixed(TestVectors.NOW, ZoneOffset.UTC))
    private val request = PresentationRequest.forTestPid("urn:zilath:test:entitlement")

    @Test
    fun `a receipt proves the outcome without carrying any claim value`() {
        val receipt = receipts.issue(TransactionId("tx-1"), request, verified = true)
        val jwt = SignedJWT.parse(receipt)
        assertThat(jwt.verify(ECDSAVerifier(signingKey.toPublicJWK()))).isTrue()
        assertThat(jwt.header.type.toString()).isEqualTo("zilath-receipt+jwt")
        val claims = jwt.jwtClaimsSet
        assertThat(claims.jwtid).isEqualTo("tx-1")
        assertThat(claims.issuer).isEqualTo(TestVectors.AUDIENCE)
        assertThat(claims.getStringClaim("outcome")).isEqualTo("verified")
        assertThat(claims.getBooleanClaim("entitled")).isTrue()
        assertThat(claims.getStringListClaim("requested_claims"))
            .containsExactly("given_name", "family_name")
        assertThat(claims.getStringClaim("request_hash")).isNotBlank()
        // The receipt must never contain claim VALUES: it proves the outcome, not the why.
        assertThat(receipt).doesNotContain("Ada")
        assertThat(jwt.payload.toString()).doesNotContain("Lovelace")
    }

    @Test
    fun `a rejected outcome is recorded as not entitled`() {
        val jwt = SignedJWT.parse(receipts.issue(TransactionId("tx-2"), request, verified = false))
        assertThat(jwt.jwtClaimsSet.getStringClaim("outcome")).isEqualTo("rejected")
        assertThat(jwt.jwtClaimsSet.getBooleanClaim("entitled")).isFalse()
    }

    @Test
    fun `the request hash is stable for the same query`() {
        val first = SignedJWT.parse(receipts.issue(TransactionId("a"), request, verified = true))
        val second = SignedJWT.parse(receipts.issue(TransactionId("b"), request, verified = true))
        assertThat(first.jwtClaimsSet.getStringClaim("request_hash"))
            .isEqualTo(second.jwtClaimsSet.getStringClaim("request_hash"))
    }
}
