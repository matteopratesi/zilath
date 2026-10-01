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
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

@OptIn(InternalZilathApi::class)
class SharedRulesTest {
    @Test
    fun `rsa keys below 2048 bits get no verifier`() {
        assertThat(acceptableJwsVerifierFor(weakRsaKey(512).toPublicJWK())).isNull()
        assertThat(acceptableJwsVerifierFor(weakRsaKey(1024).toPublicJWK())).isNull()
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
        val weak = weakRsaKey(1024)
        val strong = RSAKeyGenerator(2048).generate()
        assertThat(verifiesWithAnyAcceptableKey(signedWith(weak), listOf(weak.toPublicJWK()))).isFalse()
        assertThat(verifiesWithAnyAcceptableKey(signedWith(strong), listOf(strong.toPublicJWK()))).isTrue()
    }

    @Test
    fun `the accepted signature algorithms are the six IT-Wallet lists as MUST or RECOMMENDED`() {
        // algorithms.rst of IT-Wallet 1.4.7: ES256, ES384, ES512 (MUST), PS256, PS384, PS512 (RECOMMENDED).
        val listed = listOf("ES256", "ES384", "ES512", "PS256", "PS384", "PS512")
        assertThat(ACCEPTED_JWS_ALGORITHMS.map { it.name }).containsExactlyInAnyOrderElementsOf(listed)
        listed.forEach { assertThat(isAcceptedJwsAlgorithm(JWSAlgorithm(it))).`as`(it).isTrue() }
    }

    @Test
    fun `every other signature algorithm is refused`() {
        // RS* were accepted before; the HMAC family and none are the list's MUST NOT; ES256K and
        // the Edwards algorithms are unlisted ("not required by the current profile"); ESP* are
        // the list's COSE entries; the spelling is exact, as it is for any `alg`.
        listOf(
            "RS256",
            "RS384",
            "RS512",
            "HS256",
            "HS384",
            "HS512",
            "ES256K",
            "EdDSA",
            "Ed25519",
            "Ed448",
            "ESP256",
            "ESP384",
            "ESP512",
            "none",
            "es256",
            "Es256",
            "ps256",
            "PS224",
        ).forEach { assertThat(isAcceptedJwsAlgorithm(JWSAlgorithm(it))).`as`(it).isFalse() }
        assertThat(isAcceptedJwsAlgorithm(null)).isFalse()
    }

    @Test
    fun `a signature made with an unlisted algorithm does not verify under a key that is otherwise good`() {
        // The same 2048-bit key, the same claims: only the `alg` differs, and with it the answer.
        val strong = RSAKeyGenerator(2048).generate()
        val keys = listOf(strong.toPublicJWK())
        listOf(JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512).forEach {
            assertThat(verifiesWithAnyAcceptableKey(signedWith(strong, it), keys)).`as`(it.name).isTrue()
        }
        listOf(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512).forEach {
            assertThat(signedWith(strong, it).verify(checkNotNull(acceptableJwsVerifierFor(strong.toPublicJWK()))))
                .`as`("${it.name}: Nimbus itself verifies it")
                .isTrue()
            assertThat(verifiesWithAnyAcceptableKey(signedWith(strong, it), keys)).`as`(it.name).isFalse()
        }
    }

    @Test
    fun `the elliptic curve algorithms verify under their own curve`() {
        listOf(
            Curve.P_256 to JWSAlgorithm.ES256,
            Curve.P_384 to JWSAlgorithm.ES384,
            Curve.P_521 to JWSAlgorithm.ES512,
        ).forEach { (curve, algorithm) ->
            val key = ECKeyGenerator(curve).generate()
            val jwt = SignedJWT(JWSHeader(algorithm), JWTClaimsSet.Builder().subject("x").build())
            jwt.sign(ECDSASigner(key))
            assertThat(verifiesWithAnyAcceptableKey(jwt, listOf(key.toPublicJWK()))).`as`(algorithm.name).isTrue()
        }
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
    fun `https urls with a hostname are usable, and plain http only on the loopback names`() {
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

    @Test
    fun `printable text is bounded, on one line and well formed`() {
        assertThat(boundedPrintable("issuer not in the federation")).isEqualTo("issuer not in the federation")
        assertThat(boundedPrintable("a\r\nb\u0000c\u001bd\u0085e\u2028f\u2029g\u007f")).isEqualTo("a??b?c?d?e?f?g?")
        assertThat(boundedPrintable("x".repeat(10_000))).hasSize(200)
        // A surrogate pair cut in half by the limit is dropped, not left dangling.
        val cut = boundedPrintable("x".repeat(199) + "\uD83D\uDE00")
        assertThat(cut).isEqualTo("x".repeat(199))
        // A surrogate already unpaired in the input is replaced; a whole pair survives.
        assertThat(boundedPrintable("https://x/\uD800 and \uDC00 and \uD83D\uDE00"))
            .isEqualTo("https://x/? and ? and \uD83D\uDE00")
        // An unpaired high surrogate at the very end is replaced too, not silently dropped,
        // and so is one the limit leaves last when what follows it is not its pair.
        assertThat(boundedPrintable("issuer\uD800")).isEqualTo("issuer?")
        assertThat(boundedPrintable("x".repeat(199) + "\uD800" + "y")).isEqualTo("x".repeat(199) + "?")
    }

    @Test
    fun `a weak rsa modulus padded with zero bytes is still weak`() {
        val weak = weakRsaKey(1024)
        val padded =
            RSAKey
                .Builder(zeroPadded(weak.modulus, 256), weak.publicExponent)
                .privateKey(weak.toRSAPrivateKey())
                .build()
        // What the size check used to read: the encoded length, not the modulus.
        assertThat(padded.size()).isEqualTo(2048)
        assertThat(acceptableJwsVerifierFor(padded.toPublicJWK())).isNull()
        assertThat(verifiesWithAnyAcceptableKey(signedWith(padded), listOf(padded.toPublicJWK()))).isFalse()
    }

    private fun zeroPadded(
        value: Base64URL,
        bytes: Int,
    ): Base64URL {
        val raw = value.decode()
        return Base64URL.encode(ByteArray(bytes - raw.size) + raw)
    }

    private fun signedWith(
        key: RSAKey,
        algorithm: JWSAlgorithm = JWSAlgorithm.PS256,
    ): SignedJWT =
        SignedJWT(JWSHeader(algorithm), JWTClaimsSet.Builder().subject("x").build()).apply {
            sign(RSASSASigner(key.toRSAPrivateKey(), setOf(AllowWeakRSAKey.getInstance())))
        }
}
