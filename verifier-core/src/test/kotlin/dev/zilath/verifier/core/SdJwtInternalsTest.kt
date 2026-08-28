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

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTClaimsSet
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class SdJwtInternalsTest {
    @Test
    fun `credential without status claim has no status reference`() {
        val claims = JWTClaimsSet.Builder().claim("iss", "x").build()
        assertThat(statusReferenceOf(claims)).isNull()
    }

    @Test
    fun `status claim without status_list is a status check failure`() {
        val claims = JWTClaimsSet.Builder().claim("status", mapOf("other" to "thing")).build()
        assertThatThrownBy { statusReferenceOf(claims) }
            .isInstanceOf(SdJwtRejection::class.java)
            .extracting { (it as SdJwtRejection).reason }
            .isEqualTo(RejectionReason.STATUS_CHECK_FAILED)
    }

    @Test
    fun `status_list without uri or idx is a status check failure`() {
        val claims =
            JWTClaimsSet
                .Builder()
                .claim("status", mapOf("status_list" to mapOf("idx" to 1)))
                .build()
        assertThatThrownBy { statusReferenceOf(claims) }
            .isInstanceOf(SdJwtRejection::class.java)
            .extracting { (it as SdJwtRejection).reason }
            .isEqualTo(RejectionReason.STATUS_CHECK_FAILED)
    }

    @Test
    fun `unexpected failures map to malformed`() {
        assertThat(rejectionOf(IllegalStateException("boom")).reason).isEqualTo(RejectionReason.MALFORMED)
    }

    @Test
    fun `issuer verifier rejects keys of unsupported type`() {
        // RFC 8037 appendix A test key: only the key type matters here.
        val okpKey =
            JWK.parse("""{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}""")
        val verifier = issuerSignatureVerifier(listOf(okpKey))
        val issuerJwt = TestVectors.vector().substringBefore('~')
        val outcome = runBlocking { verifier.checkSignature(issuerJwt) }
        assertThat(outcome).isNull()
    }

    @Test
    fun `trust_chain header parameter reaches the trust input`() {
        val issuerJwt = parseIssuerJwt(TestVectors.vector())
        assertThat(trustInputOf(issuerJwt).trustChain).isEmpty()
        val withChain =
            com.nimbusds.jwt.SignedJWT(
                com.nimbusds.jose.JWSHeader
                    .Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                    .customParam("trust_chain", listOf("statement-a", "statement-b"))
                    .build(),
                com.nimbusds.jwt.JWTClaimsSet
                    .Builder()
                    .issuer("https://issuer.example")
                    .build(),
            )
        withChain.sign(
            com.nimbusds.jose.crypto
                .ECDSASigner(TestVectors.issuerEcKey),
        )
        assertThat(trustInputOf(withChain).trustChain).containsExactly("statement-a", "statement-b")
    }

    @Test
    fun `sd_hash changes when a disclosure is withheld`() {
        val compact = TestVectors.vector()
        val withheld =
            compact
                .split('~')
                .toMutableList()
                .also { it.removeAt(1) }
                .joinToString("~")
        assertThat(sdHashOf(withheld)).isNotEqualTo(sdHashOf(compact))
    }
}
