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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.opts.AllowWeakRSAKey
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

@OptIn(InternalZilathApi::class)
class SharedRulesTest {
    @Test
    fun `rsa keys below 2048 bits get no verifier`() {
        assertThat(acceptableJwsVerifierFor(weakRsaKey(512))).isNull()
        assertThat(acceptableJwsVerifierFor(weakRsaKey(1024))).isNull()
        assertThat(acceptableJwsVerifierFor(RSAKeyGenerator(2048).generate().toPublicJWK())).isNotNull()
    }

    @Test
    fun `only the three nist curves get a verifier`() {
        listOf(Curve.P_256, Curve.P_384, Curve.P_521).forEach { curve ->
            assertThat(acceptableJwsVerifierFor(ECKeyGenerator(curve).generate().toPublicJWK())).isNotNull()
        }
        assertThat(acceptableJwsVerifierFor(OctetSequenceKeyGenerator(256).generate())).isNull()
    }

    @Test
    fun `a signature under a weak rsa key does not verify, a strong one does`() {
        val weak = weakRsaKey(1024, private = true)
        val strong = RSAKeyGenerator(2048).generate()
        assertThat(verifiesWithAnyAcceptableKey(signedWith(weak), listOf(weak.toPublicJWK()))).isFalse()
        assertThat(verifiesWithAnyAcceptableKey(signedWith(strong), listOf(strong.toPublicJWK()))).isTrue()
    }

    @Test
    fun `an unusable key does not stop the next one from being tried`() {
        val ec = ECKeyGenerator(Curve.P_256).generate()
        val jwt = SignedJWT(JWSHeader(JWSAlgorithm.ES256), JWTClaimsSet.Builder().subject("x").build())
        jwt.sign(ECDSASigner(ec))
        val keys = listOf(RSAKeyGenerator(2048).generate().toPublicJWK(), ec.toPublicJWK())
        assertThat(verifiesWithAnyAcceptableKey(jwt, keys)).isTrue()
    }

    @Test
    fun `media types compare as rfc 7515 says`() {
        listOf("statuslist+jwt", "application/statuslist+jwt", "StatusList+JWT", " statuslist+jwt ").forEach {
            assertThat(mediaTypeMatches(it, "statuslist+jwt")).`as`(it).isTrue()
        }
        listOf(null, "statuslist+cwt", "jwt", "application/statuslist+jwt;x=1", "foo/statuslist+jwt").forEach {
            assertThat(mediaTypeMatches(it, "statuslist+jwt")).`as`(it.toString()).isFalse()
        }
    }

    @Test
    fun `only https urls with a hostname are usable`() {
        listOf(
            "https://status.example/1",
            "https://status.example/1?x=y",
            "http://localhost:8080/status",
            "http://127.0.0.1/status",
        ).forEach { assertThat(usableHttpsUriOrNull(it)).`as`(it).isNotNull() }
        listOf(
            "http://169.254.169.254/latest/meta-data/",
            "http://status.example/1",
            "file:///etc/passwd",
            "https://user:pw@status.example/1",
            "https://2130706433/status/1",
            "https://0177.0.0.1/status/1",
            "https://[fe80::1]/status",
            "https://status.example/1#frag",
            "ftp://status.example/1",
            "not a uri at all",
            "",
        ).forEach { assertThat(usableHttpsUriOrNull(it)).`as`(it).isNull() }
    }

    private fun signedWith(key: RSAKey): SignedJWT =
        SignedJWT(JWSHeader(JWSAlgorithm.RS256), JWTClaimsSet.Builder().subject("x").build()).apply {
            sign(RSASSASigner(key.toRSAPrivateKey(), setOf(AllowWeakRSAKey.getInstance())))
        }

    /** Nimbus refuses to GENERATE a key this small, which is the whole point: it will verify with one. */
    private fun weakRsaKey(
        bits: Int,
        private: Boolean = false,
    ): RSAKey {
        val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()
        val builder = RSAKey.Builder(pair.public as RSAPublicKey)
        return if (private) builder.privateKey(pair.private as RSAPrivateKey).build() else builder.build()
    }
}
