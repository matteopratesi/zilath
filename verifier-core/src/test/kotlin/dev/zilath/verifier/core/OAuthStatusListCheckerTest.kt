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
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Date
import java.util.zip.Deflater

class OAuthStatusListCheckerTest {
    private val issuerKey = ECKeyGenerator(Curve.P_256).keyID("issuer").generate()
    private val attackerKey = ECKeyGenerator(Curve.P_256).keyID("attacker").generate()

    private val now = Instant.parse("2026-08-29T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private val issuer = "https://issuer.example"
    private val uri = "https://status.example/1"

    /** What the verifier would hand the checker after trusting the credential's issuer. */
    private val trust = StatusIssuerTrust(issuer, listOf(issuerKey.toPublicJWK()))

    private fun deflate(raw: ByteArray): String {
        val deflater = Deflater()
        deflater.setInput(raw)
        deflater.finish()
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(64)
        while (!deflater.finished()) {
            out.write(buffer, 0, deflater.deflate(buffer))
        }
        deflater.end()
        return Base64URL.encode(out.toByteArray()).toString()
    }

    @Suppress("LongParameterList") // every axis is one thing a test needs to bend
    private fun token(
        bits: Int = 1,
        rawList: ByteArray = byteArrayOf(0),
        signWith: ECKey = issuerKey,
        iss: String? = issuer,
        sub: String? = uri,
        typ: String? = "statuslist+jwt",
        expiresAt: Instant? = null,
    ): String {
        val claims =
            JWTClaimsSet
                .Builder()
                .apply {
                    iss?.let { issuer(it) }
                    sub?.let { subject(it) }
                    expiresAt?.let { expirationTime(Date.from(it)) }
                    issueTime(Date.from(now))
                    claim("status_list", mapOf("bits" to bits, "lst" to deflate(rawList)))
                }.build()
        val header =
            JWSHeader
                .Builder(JWSAlgorithm.ES256)
                .apply { typ?.let { type(JOSEObjectType(it)) } }
                .build()
        return SignedJWT(header, claims).apply { sign(ECDSASigner(signWith)) }.serialize()
    }

    private fun checkerFor(token: String) = OAuthStatusListChecker({ token }, clock)

    private fun statusOf(
        token: String,
        index: Int = 0,
        trust: StatusIssuerTrust = this.trust,
    ) = checkerFor(token).check(StatusReference(uri, index), trust)

    // --- what the list says, once it is believable -------------------------------------

    @Test
    fun `bit set at index means revoked, clear bit means valid`() {
        // bits=1, one byte, only index 3 set: 0b0000_1000
        val t = token(rawList = byteArrayOf(0b0000_1000))
        assertThat(statusOf(t, index = 3)).isEqualTo(CredentialStatus.REVOKED)
        assertThat(statusOf(t, index = 2)).isEqualTo(CredentialStatus.VALID)
        assertThat(statusOf(t, index = 7)).isEqualTo(CredentialStatus.VALID)
    }

    @Test
    fun `two bit entries are decoded at the right offset`() {
        // bits=2, one byte holding entries [0..3]: entry 1 has value 2 -> 0b0000_1000
        val t = token(bits = 2, rawList = byteArrayOf(0b0000_1000))
        assertThat(statusOf(t, index = 1)).isEqualTo(CredentialStatus.REVOKED)
        assertThat(statusOf(t, index = 0)).isEqualTo(CredentialStatus.VALID)
    }

    // --- the checks that decide whether to believe it at all ---------------------------
    //
    // Every case below would have returned VALID before the signature and claim checks
    // existed. That is the point of the fix: a revoked credential could be reported as
    // valid by anyone able to answer for the status URI.

    @Test
    fun `a status list signed by someone else is unknown, not valid`() {
        val forged = token(rawList = byteArrayOf(0), signWith = attackerKey)
        assertThat(statusOf(forged)).isEqualTo(CredentialStatus.UNKNOWN)
    }

    @Test
    fun `a forged list claiming a revoked credential is valid does not get believed`() {
        // The attacker serves an all-zero list — "nobody is revoked" — signed with a key
        // the verifier has no reason to trust. This is the attack the gap allowed.
        val forged = token(rawList = byteArrayOf(0), signWith = attackerKey)
        assertThat(statusOf(forged)).isEqualTo(CredentialStatus.UNKNOWN)

        // The same list, signed by the issuer we do trust, is believed.
        val genuine = token(rawList = byteArrayOf(0), signWith = issuerKey)
        assertThat(statusOf(genuine)).isEqualTo(CredentialStatus.VALID)
    }

    @Test
    fun `a status list issued by a third party is unknown`() {
        val thirdParty = token(iss = "https://someone-else.example")
        assertThat(statusOf(thirdParty)).isEqualTo(CredentialStatus.UNKNOWN)
    }

    @Test
    fun `a token whose sub does not match the referenced uri is unknown`() {
        // A genuine, correctly signed token for a DIFFERENT list must not be replayed here.
        val otherList = token(sub = "https://status.example/999")
        assertThat(statusOf(otherList)).isEqualTo(CredentialStatus.UNKNOWN)
    }

    @Test
    fun `a token without the statuslist typ is unknown`() {
        assertThat(statusOf(token(typ = null))).isEqualTo(CredentialStatus.UNKNOWN)
        assertThat(statusOf(token(typ = "JWT"))).isEqualTo(CredentialStatus.UNKNOWN)
    }

    @Test
    fun `an expired token is unknown, and one still valid is believed`() {
        assertThat(statusOf(token(expiresAt = now.minusSeconds(1)))).isEqualTo(CredentialStatus.UNKNOWN)
        assertThat(statusOf(token(expiresAt = now.plusSeconds(60)))).isEqualTo(CredentialStatus.VALID)
    }

    @Test
    fun `no trusted keys means unknown`() {
        assertThat(statusOf(token(), trust = StatusIssuerTrust(issuer, emptyList())))
            .isEqualTo(CredentialStatus.UNKNOWN)
    }

    @Test
    fun `a credential without an issuer cannot have its status trusted`() {
        assertThat(statusOf(token(), trust = StatusIssuerTrust(null, listOf(issuerKey.toPublicJWK()))))
            .isEqualTo(CredentialStatus.UNKNOWN)
    }

    // --- failures that already degraded closed, kept honest ----------------------------

    @Test
    fun `index outside the list is unknown`() {
        assertThat(statusOf(token(), index = 999)).isEqualTo(CredentialStatus.UNKNOWN)
    }

    @Test
    fun `fetch failure degrades to unknown`() {
        val checker = OAuthStatusListChecker({ error("network down") }, clock)
        assertThat(checker.check(StatusReference(uri, 0), trust)).isEqualTo(CredentialStatus.UNKNOWN)
    }

    @Test
    fun `malformed token degrades to unknown`() {
        assertThat(statusOf("not-a-jwt")).isEqualTo(CredentialStatus.UNKNOWN)
    }

    @Test
    fun `oversized status list degrades to unknown instead of exhausting the heap`() {
        // 4 MiB of zeros compresses to a few KiB: a classic zip-bomb shape.
        assertThat(statusOf(token(rawList = ByteArray(4 * 1024 * 1024)))).isEqualTo(CredentialStatus.UNKNOWN)
    }

    @Test
    fun `unsupported bits size degrades to unknown`() {
        assertThat(statusOf(token(bits = 3))).isEqualTo(CredentialStatus.UNKNOWN)
    }
}
