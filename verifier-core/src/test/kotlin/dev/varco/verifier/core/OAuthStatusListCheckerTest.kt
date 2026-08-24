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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.util.zip.Deflater

class OAuthStatusListCheckerTest {
    private val signingKey = ECKeyGenerator(Curve.P_256).keyID("status-signer").generate()

    private fun statusListToken(
        bits: Int,
        rawList: ByteArray,
    ): String {
        val deflater = Deflater()
        deflater.setInput(rawList)
        deflater.finish()
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(64)
        while (!deflater.finished()) {
            out.write(buffer, 0, deflater.deflate(buffer))
        }
        deflater.end()
        val claims =
            JWTClaimsSet
                .Builder()
                .claim("status_list", mapOf("bits" to bits, "lst" to Base64URL.encode(out.toByteArray()).toString()))
                .build()
        val jwt = SignedJWT(JWSHeader(JWSAlgorithm.ES256), claims)
        jwt.sign(ECDSASigner(signingKey))
        return jwt.serialize()
    }

    @Test
    fun `bit set at index means revoked, clear bit means valid`() {
        // bits=1, one byte, only index 3 set: 0b0000_1000
        val token = statusListToken(bits = 1, rawList = byteArrayOf(0b0000_1000))
        val checker = OAuthStatusListChecker { token }
        assertThat(checker.check(StatusReference("https://status.example/1", 3))).isEqualTo(CredentialStatus.REVOKED)
        assertThat(checker.check(StatusReference("https://status.example/1", 2))).isEqualTo(CredentialStatus.VALID)
        assertThat(checker.check(StatusReference("https://status.example/1", 7))).isEqualTo(CredentialStatus.VALID)
    }

    @Test
    fun `two bit entries are decoded at the right offset`() {
        // bits=2, one byte holding entries [0..3]: entry 1 has value 2 -> 0b0000_1000
        val token = statusListToken(bits = 2, rawList = byteArrayOf(0b0000_1000))
        val checker = OAuthStatusListChecker { token }
        assertThat(checker.check(StatusReference("u", 1))).isEqualTo(CredentialStatus.REVOKED)
        assertThat(checker.check(StatusReference("u", 0))).isEqualTo(CredentialStatus.VALID)
    }

    @Test
    fun `index outside the list is unknown`() {
        val token = statusListToken(bits = 1, rawList = byteArrayOf(0))
        val checker = OAuthStatusListChecker { token }
        assertThat(checker.check(StatusReference("u", 999))).isEqualTo(CredentialStatus.UNKNOWN)
    }

    @Test
    fun `fetch failure degrades to unknown`() {
        val checker = OAuthStatusListChecker { error("network down") }
        assertThat(checker.check(StatusReference("u", 0))).isEqualTo(CredentialStatus.UNKNOWN)
    }

    @Test
    fun `malformed token degrades to unknown`() {
        val checker = OAuthStatusListChecker { "not-a-jwt" }
        assertThat(checker.check(StatusReference("u", 0))).isEqualTo(CredentialStatus.UNKNOWN)
    }

    @Test
    fun `unsupported bits size degrades to unknown`() {
        val token = statusListToken(bits = 3, rawList = byteArrayOf(0))
        val checker = OAuthStatusListChecker { token }
        assertThat(checker.check(StatusReference("u", 0))).isEqualTo(CredentialStatus.UNKNOWN)
    }
}
