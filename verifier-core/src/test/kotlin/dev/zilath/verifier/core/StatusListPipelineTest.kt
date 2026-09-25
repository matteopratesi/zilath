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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.time.Clock
import java.time.ZoneOffset
import java.util.Date
import java.util.zip.Deflater

/**
 * The status list end to end: a credential with a status reference, verified with
 * [OAuthStatusListChecker] and a token shaped as IT-Wallet 1.4.6 §11.4.4.1.1 shows it —
 * `typ` in the long form some issuers write, and no `iss`. The fourth internal review found
 * such a presentation of a genuine credential ending STATUS_CHECK_FAILED.
 */
class StatusListPipelineTest {
    private val uri = "https://status.example/lists/1"

    private fun deflated(raw: ByteArray): String {
        val deflater =
            Deflater().apply {
                setInput(raw)
                finish()
            }
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(64)
        while (!deflater.finished()) out.write(buffer, 0, deflater.deflate(buffer))
        deflater.end()
        return Base64URL.encode(out.toByteArray()).toString()
    }

    /** A bits=2 list whose entry 3 holds [value]; everything else is valid. */
    private fun token(
        value: Int,
        typ: String = "application/statuslist+jwt",
    ): String {
        val claims =
            JWTClaimsSet
                .Builder()
                .subject(uri)
                .issueTime(Date.from(TestVectors.NOW))
                .expirationTime(Date.from(TestVectors.NOW.plusSeconds(3600)))
                .claim("ttl", 43_200)
                .claim("status_list", mapOf("bits" to 2, "lst" to deflated(byteArrayOf((value shl 6).toByte()))))
                .build()
        val header =
            JWSHeader
                .Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType(typ))
                .keyID("issuer-ec")
                .build()
        return SignedJWT(header, claims).apply { sign(ECDSASigner(TestVectors.issuerEcKey)) }.serialize()
    }

    private fun verifyAgainst(token: String): VerificationResult {
        val checker = OAuthStatusListChecker({ token }, Clock.fixed(TestVectors.NOW, ZoneOffset.UTC))
        return verifyPresentation(TestVectors.vector(statusUri = uri, statusIndex = 3), testContext(status = checker))
    }

    @Test
    fun `a genuine credential with an iss-less long-typ status list verifies`() {
        assertThat(verifyAgainst(token(0))).isInstanceOf(VerificationResult.Verified::class.java)
    }

    @Test
    fun `each non-zero status denies with its own reason`() {
        assertThat(verifyAgainst(token(1)))
            .isEqualTo(VerificationResult.Rejected(RejectionReason.REVOKED, "credential is revoked"))
        assertThat(verifyAgainst(token(2)))
            .isEqualTo(VerificationResult.Rejected(RejectionReason.SUSPENDED, "credential is suspended"))
        assertThat(verifyAgainst(token(3)))
            .isEqualTo(VerificationResult.Rejected(RejectionReason.STATUS_NOT_VALID, "credential status is not valid"))
    }

    @Test
    fun `a status list of another type still fails the check`() {
        assertThat(verifyAgainst(token(0, typ = "statuslist+cwt")))
            .isEqualTo(
                VerificationResult.Rejected(
                    RejectionReason.STATUS_CHECK_FAILED,
                    "credential status could not be determined",
                ),
            )
    }
}
