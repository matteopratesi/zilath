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
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.opts.AllowWeakRSAKey
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.time.Clock
import java.time.Duration
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
        signWith: JWK = issuerKey,
        iss: String? = issuer,
        sub: String? = uri,
        typ: String? = "statuslist+jwt",
        expiresAt: Instant? = null,
        issuedAt: Instant? = now,
        rawClaims: Map<String, Any> = emptyMap(),
    ): String {
        val claims =
            JWTClaimsSet
                .Builder()
                .apply {
                    iss?.let { issuer(it) }
                    sub?.let { subject(it) }
                    expiresAt?.let { expirationTime(Date.from(it)) }
                    issuedAt?.let { issueTime(Date.from(it)) }
                    claim("status_list", mapOf("bits" to bits, "lst" to deflate(rawList)))
                    rawClaims.forEach { (name, value) -> claim(name, value) }
                }.build()
        val rsa = signWith is RSAKey
        val header =
            JWSHeader
                .Builder(if (rsa) JWSAlgorithm.RS256 else JWSAlgorithm.ES256)
                .apply { typ?.let { type(JOSEObjectType(it)) } }
                .build()
        val signer =
            if (rsa) {
                RSASSASigner(signWith.toRSAKey().toRSAPrivateKey(), setOf(AllowWeakRSAKey.getInstance()))
            } else {
                ECDSASigner(signWith.toECKey())
            }
        return SignedJWT(header, claims).apply { sign(signer) }.serialize()
    }

    private fun checkerFor(token: String) = OAuthStatusListChecker({ token }, clock)

    /** A fetcher that records every URI it is asked for, and serves [token]. */
    private class RecordingFetcher(
        private val token: String,
    ) : StatusListFetcher {
        val asked = mutableListOf<String>()

        override fun fetch(uri: String): String = token.also { asked.add(uri) }
    }

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
        assertThat(statusOf(t, index = 1)).isEqualTo(CredentialStatus.SUSPENDED)
        assertThat(statusOf(t, index = 0)).isEqualTo(CredentialStatus.VALID)
    }

    @Test
    fun `each status type is reported as what it is, and only zero is valid`() {
        // bits=4, two entries per byte, low nibble first (draft §4.1):
        // idx0=0x0 idx1=0x1 | idx2=0x2 idx3=0xF | idx4=0x3 idx5=0x0
        // Before the fourth internal review every non-zero value came back REVOKED, so a
        // suspended card, or one IT-Wallet merely asks the wallet to refresh (UPDATE 0x03,
        // ATTRIBUTE_UPDATE 0x0F), was logged and receipted as withdrawn for good.
        val t = token(bits = 4, rawList = byteArrayOf(0x10, 0xF2.toByte(), 0x03))
        assertThat(statusOf(t, index = 0)).isEqualTo(CredentialStatus.VALID)
        assertThat(statusOf(t, index = 1)).isEqualTo(CredentialStatus.REVOKED)
        assertThat(statusOf(t, index = 2)).isEqualTo(CredentialStatus.SUSPENDED)
        assertThat(statusOf(t, index = 3)).isEqualTo(CredentialStatus.APPLICATION_SPECIFIC)
        assertThat(statusOf(t, index = 4)).isEqualTo(CredentialStatus.APPLICATION_SPECIFIC)
        assertThat(statusOf(t, index = 5)).isEqualTo(CredentialStatus.VALID)
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
    fun `a status list signed with a weak rsa issuer key is unknown`() {
        // The fourth internal review: with a factorable issuer key, a stranger forges a
        // "valid" answer for a revoked credential. The key rule skips it like any unusable key.
        val weak = weakRsaKey(1024)
        assertThat(statusOf(token(signWith = weak), trust = StatusIssuerTrust(issuer, listOf(weak.toPublicJWK()))))
            .isEqualTo(CredentialStatus.UNKNOWN)
        val strong = RSAKeyGenerator(2048).generate()
        assertThat(statusOf(token(signWith = strong), trust = StatusIssuerTrust(issuer, listOf(strong.toPublicJWK()))))
            .isEqualTo(CredentialStatus.VALID)
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
    fun `a token without iss signed by the issuer key is believed`() {
        // Neither the draft (§5.1) nor IT-Wallet 1.4.6 requires iss, and both examples omit
        // it: requiring it denied every holder of such an issuer. The signature under the
        // issuer's own key is what binds the token to it; an iss that IS present must still
        // match (the test above).
        assertThat(statusOf(token(iss = null, rawList = byteArrayOf(0b0000_0010)), index = 1))
            .isEqualTo(CredentialStatus.REVOKED)
        assertThat(statusOf(token(iss = null))).isEqualTo(CredentialStatus.VALID)
        assertThat(statusOf(token(iss = null, signWith = attackerKey))).isEqualTo(CredentialStatus.UNKNOWN)
    }

    @Test
    fun `a status uri that is not a usable https url never reaches the fetcher`() {
        // For a caller building a StatusReference by hand; the verifier refuses such a
        // credential before it gets here. The same shape rule as the federation URLs.
        listOf(
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "https://user:pw@status.example/1",
            "https://2130706433/status/1",
            "https://[fe80::1]:8080/status",
            "ftp://status.example/1",
            "not a uri at all",
            "",
        ).forEach { bad ->
            val fetcher = RecordingFetcher(token(sub = bad))
            val status = OAuthStatusListChecker(fetcher, clock).check(StatusReference(bad, 0), trust)
            assertThat(status).`as`(bad).isEqualTo(CredentialStatus.UNKNOWN)
            assertThat(fetcher.asked).`as`(bad).isEmpty()
        }
    }

    @Test
    fun `a status uri with a query string is fetched`() {
        val withQuery = "https://status.example/lists?id=1"
        val fetcher = RecordingFetcher(token(sub = withQuery))
        val status = OAuthStatusListChecker(fetcher, clock).check(StatusReference(withQuery, 0), trust)
        assertThat(status).isEqualTo(CredentialStatus.VALID)
        assertThat(fetcher.asked).containsExactly(withQuery)
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
        listOf("statuslist+cwt", "jwt", "application/statuslist+jwt;x=1", "foo/statuslist+jwt").forEach {
            assertThat(statusOf(token(typ = it))).`as`(it).isEqualTo(CredentialStatus.UNKNOWN)
        }
    }

    @Test
    fun `the typ forms rfc 7515 makes equivalent are all believed`() {
        // application/ is implied and media types are case-insensitive (RFC 7515 §4.1.9):
        // a literal comparison turned these genuine tokens into denials.
        listOf("statuslist+jwt", "application/statuslist+jwt", "StatusList+JWT", "APPLICATION/statuslist+jwt")
            .forEach { assertThat(statusOf(token(typ = it))).`as`(it).isEqualTo(CredentialStatus.VALID) }
    }

    @Test
    fun `an expired token is unknown, and one still valid is believed`() {
        assertThat(statusOf(token(expiresAt = now.minusSeconds(1)))).isEqualTo(CredentialStatus.UNKNOWN)
        assertThat(statusOf(token(expiresAt = now.plusSeconds(60)))).isEqualTo(CredentialStatus.VALID)
    }

    @Test
    fun `the expiry instant itself is already expired`() {
        // RFC 7519 4.1.4 wants the current time strictly before exp, and this is the same
        // boundary the credential's own expiry uses. Pinned because an off-by-one here is
        // invisible until a clock lands exactly on it.
        assertThat(statusOf(token(expiresAt = now))).isEqualTo(CredentialStatus.UNKNOWN)
    }

    @Test
    fun `dates that wrap around in Nimbus are not believed`() {
        // x * 1000 overflows a long: 18446745861714352 read as now, 18446745861717952 as an
        // hour ahead. Neither is a date; both used to pass as a fresh iat and a valid exp.
        assertThat(
            statusOf(token(rawClaims = mapOf("iat" to 18_446_745_861_714_352L))),
        ).isEqualTo(CredentialStatus.UNKNOWN)
        assertThat(
            statusOf(token(rawClaims = mapOf("exp" to 18_446_745_861_717_952L))),
        ).isEqualTo(CredentialStatus.UNKNOWN)
        assertThat(statusOf(token(rawClaims = mapOf("iat" to now.toEpochMilli())))).isEqualTo(CredentialStatus.UNKNOWN)
        assertThat(
            statusOf(token(rawClaims = mapOf("exp" to now.plusSeconds(60).epochSecond))),
        ).isEqualTo(CredentialStatus.VALID)
    }

    @Test
    fun `a token with no iat is unknown`() {
        // iat is REQUIRED by the draft, and it is what the freshness policy stands on.
        assertThat(statusOf(token(issuedAt = null))).isEqualTo(CredentialStatus.UNKNOWN)
    }

    @Test
    fun `a stale token is unknown even though it is correctly signed`() {
        // The replay a missing exp would otherwise allow forever: a genuine "nobody is
        // revoked" list, captured and served again long after someone was revoked.
        val stale = token(issuedAt = now.minus(Duration.ofDays(1)).minusSeconds(1))
        assertThat(statusOf(stale)).isEqualTo(CredentialStatus.UNKNOWN)

        val fresh = token(issuedAt = now.minus(Duration.ofHours(23)))
        assertThat(statusOf(fresh)).isEqualTo(CredentialStatus.VALID)
    }

    @Test
    fun `a token issued in the future beyond the skew tolerance is unknown`() {
        assertThat(statusOf(token(issuedAt = now.plusSeconds(120)))).isEqualTo(CredentialStatus.UNKNOWN)
        // A minute of the issuer's clock running ahead is tolerated, not punished.
        assertThat(statusOf(token(issuedAt = now.plusSeconds(30)))).isEqualTo(CredentialStatus.VALID)
    }

    @Test
    fun `the freshness window is configurable`() {
        val strict = OAuthStatusListChecker({ token(issuedAt = now.minusSeconds(120)) }, clock, Duration.ofMinutes(1))
        assertThat(strict.check(StatusReference(uri, 0), trust)).isEqualTo(CredentialStatus.UNKNOWN)
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
    fun `a negative index is unknown, not a read of somebody else's entry`() {
        // -1/8 is 0, so a negative index passes the byteIndex bounds check, and the JVM
        // masks a negative shift to (n and 31): the read lands on a different credential.
        assertThat(statusOf(token(rawList = byteArrayOf(0b0111_1111)), index = -1))
            .isEqualTo(CredentialStatus.UNKNOWN)
    }

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
        // Twice the default cap in zeros compresses to a few tens of KiB: a zip-bomb shape.
        val bomb = ByteArray(2 * OAuthStatusListChecker.DEFAULT_MAX_INFLATED_BYTES)
        assertThat(statusOf(token(rawList = bomb))).isEqualTo(CredentialStatus.UNKNOWN)
    }

    @Test
    fun `an eight bit list of more than a million entries is read`() {
        // 2^20 + 1 entries at bits=8: one byte beyond the cap the fourth internal review
        // found, which turned every lookup in a large IT-Wallet list into a denial.
        val entries = (1 shl 20) + 1
        val list = ByteArray(entries).also { it[entries - 1] = 0x02 }
        val t = token(bits = 8, rawList = list)
        assertThat(statusOf(t, index = entries - 1)).isEqualTo(CredentialStatus.SUSPENDED)
        assertThat(statusOf(t, index = 0)).isEqualTo(CredentialStatus.VALID)
    }

    @Test
    fun `the inflation cap is configurable and bites exactly past it`() {
        val atCap = token(rawList = ByteArray(1024))
        val overCap = token(rawList = ByteArray(1025))
        val capped = { t: String -> OAuthStatusListChecker({ t }, clock, maxInflatedBytes = 1024) }
        assertThat(capped(atCap).check(StatusReference(uri, 1024 * 8 - 1), trust)).isEqualTo(CredentialStatus.VALID)
        assertThat(capped(overCap).check(StatusReference(uri, 0), trust)).isEqualTo(CredentialStatus.UNKNOWN)
        assertThatThrownBy { OAuthStatusListChecker({ atCap }, clock, maxInflatedBytes = 0) }
            .isInstanceOf(IllegalArgumentException::class.java)
    }

    @Test
    fun `a token longer than any list under the cap could make is not parsed`() {
        // 1 KiB of inflated list allows 2 KiB plus 64 KiB of everything else; this token is
        // correctly signed and would otherwise be believed.
        val padded =
            SignedJWT(
                JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType("statuslist+jwt")).build(),
                JWTClaimsSet
                    .Builder()
                    .subject(uri)
                    .issueTime(Date.from(now))
                    .claim("pad", "x".repeat(70_000))
                    .claim("status_list", mapOf("bits" to 1, "lst" to deflate(byteArrayOf(0))))
                    .build(),
            ).apply { sign(ECDSASigner(issuerKey)) }.serialize()
        val capped = OAuthStatusListChecker({ padded }, clock, maxInflatedBytes = 1024)
        assertThat(capped.check(StatusReference(uri, 0), trust)).isEqualTo(CredentialStatus.UNKNOWN)
        assertThat(checkerFor(padded).check(StatusReference(uri, 0), trust)).isEqualTo(CredentialStatus.VALID)
    }

    @Test
    fun `unsupported bits size degrades to unknown`() {
        assertThat(statusOf(token(bits = 3))).isEqualTo(CredentialStatus.UNKNOWN)
    }
}
