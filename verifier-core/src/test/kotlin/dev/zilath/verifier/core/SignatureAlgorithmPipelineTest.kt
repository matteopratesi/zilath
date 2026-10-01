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
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.JSONObjectUtils
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * The signature algorithms the pipeline accepts: ES256, ES384, ES512, PS256, PS384 and PS512,
 * the ones IT-Wallet 1.4.7 lists as MUST or RECOMMENDED (test ATT-004, [ACCEPTED_JWS_ALGORITHMS]).
 * Every refusal here is paired with an acceptance of the same key and claims under a listed
 * algorithm, so that what is refused is the `alg` and nothing else: RS256 under a good
 * 3072-bit key verifies mathematically, and was accepted before 1.4.7.
 */
class SignatureAlgorithmPipelineTest {
    private val rsa = RSAKeyGenerator(3072).keyID("rsa").generate()
    private val unlistedRsa = listOf(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512)
    private val listedRsa = listOf(JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512)

    private val issuerAlgorithmRefused =
        VerificationResult.Rejected(
            RejectionReason.INVALID_ISSUER_SIGNATURE,
            "issuer signature algorithm is not accepted",
        )
    private val keyBindingAlgorithmRefused =
        VerificationResult.Rejected(
            RejectionReason.INVALID_KEY_BINDING,
            "key binding signature algorithm is not accepted",
        )

    private fun verifyIssuedBy(
        key: JWK,
        algorithm: JWSAlgorithm,
    ) = verifyPresentation(
        TestVectors.vector(issuerSigningKey = key, issuerAlgorithm = algorithm),
        testContext(trust = TestVectors.trustIssuer(key)),
    )

    private fun verifyHeldBy(
        key: JWK,
        algorithm: JWSAlgorithm,
    ) = verifyPresentation(TestVectors.vector(holderSigningKey = key, holderAlgorithm = algorithm))

    // --- the issuer JWT ---------------------------------------------------------------

    @Test
    fun `an issuer JWT signed with a listed algorithm verifies`() {
        listedRsa.forEach {
            assertThat(verifyIssuedBy(rsa, it)).`as`(it.name).isInstanceOf(VerificationResult.Verified::class.java)
        }
        listOf(Curve.P_256 to JWSAlgorithm.ES256, Curve.P_384 to JWSAlgorithm.ES384, Curve.P_521 to JWSAlgorithm.ES512)
            .forEach { (curve, algorithm) ->
                val ec = ECKeyGenerator(curve).keyID("ec").generate()
                assertThat(verifyIssuedBy(ec, algorithm))
                    .`as`(algorithm.name)
                    .isInstanceOf(VerificationResult.Verified::class.java)
            }
    }

    @Test
    fun `an issuer JWT signed RS256, RS384 or RS512 is refused under a key that verifies it`() {
        unlistedRsa.forEach {
            assertThat(verifyIssuedBy(rsa, it)).`as`(it.name).isEqualTo(issuerAlgorithmRefused)
        }
    }

    @Test
    fun `an issuer JWT with any other unlisted algorithm is refused`() {
        // The header is rewritten on a genuine ES256 presentation: the signature is not the
        // point, the refusal comes first and says why. `none` is no JWS at all and does not parse.
        val genuine = TestVectors.vector()
        listOf("HS256", "HS384", "HS512", "ES256K", "EdDSA", "Ed25519", "ESP256", "RS256", "es256").forEach {
            assertThat(verifyPresentation(withHeaderAlgorithm(genuine, issuerJwt = true, algorithm = it)))
                .`as`(it)
                .isEqualTo(issuerAlgorithmRefused)
        }
        assertThat(verifyPresentation(withHeaderAlgorithm(genuine, issuerJwt = true, algorithm = "none")))
            .isEqualTo(VerificationResult.Rejected(RejectionReason.MALFORMED, "issuer JWT does not parse"))
    }

    @Test
    fun `the issuer signature check refuses an unlisted algorithm by itself`() {
        // Below the pipeline's own check, in the verifier handed to the EUDI library: the
        // rule must hold even if nothing is asked before it.
        val verifier = issuerSignatureVerifier(listOf(rsa.toPublicJWK()))
        listedRsa.forEach {
            val issuerJwt = TestVectors.vector(issuerSigningKey = rsa, issuerAlgorithm = it).substringBefore('~')
            assertThat(runBlocking { verifier.checkSignature(issuerJwt) }).`as`(it.name).isNotNull()
        }
        unlistedRsa.forEach {
            val issuerJwt = TestVectors.vector(issuerSigningKey = rsa, issuerAlgorithm = it).substringBefore('~')
            assertThat(runBlocking { verifier.checkSignature(issuerJwt) }).`as`(it.name).isNull()
        }
    }

    // --- the key binding JWT ----------------------------------------------------------

    @Test
    fun `a key binding JWT signed with a listed algorithm verifies`() {
        listedRsa.forEach {
            assertThat(verifyHeldBy(rsa, it)).`as`(it.name).isInstanceOf(VerificationResult.Verified::class.java)
        }
        listOf(Curve.P_256 to JWSAlgorithm.ES256, Curve.P_384 to JWSAlgorithm.ES384, Curve.P_521 to JWSAlgorithm.ES512)
            .forEach { (curve, algorithm) ->
                val ec = ECKeyGenerator(curve).keyID("holder-ec").generate()
                assertThat(verifyHeldBy(ec, algorithm))
                    .`as`(algorithm.name)
                    .isInstanceOf(VerificationResult.Verified::class.java)
            }
    }

    @Test
    fun `a key binding JWT signed RS256, RS384 or RS512 is refused under a key that verifies it`() {
        unlistedRsa.forEach {
            assertThat(verifyHeldBy(rsa, it)).`as`(it.name).isEqualTo(keyBindingAlgorithmRefused)
        }
    }

    @Test
    fun `a key binding JWT with any other unlisted algorithm is refused`() {
        val genuine = TestVectors.vector()
        listOf("HS256", "HS512", "ES256K", "EdDSA", "ESP256", "RS256", "es256").forEach {
            assertThat(verifyPresentation(withHeaderAlgorithm(genuine, issuerJwt = false, algorithm = it)))
                .`as`(it)
                .isEqualTo(keyBindingAlgorithmRefused)
        }
    }

    @Test
    fun `the key binding check refuses an unlisted algorithm by itself`() {
        val claims =
            buildJsonObject {
                putJsonObject("cnf") { put("jwk", Json.parseToJsonElement(rsa.toPublicJWK().toJSONString())) }
            }
        val verifier = checkNotNull(holderKeyBindingVerifier().keyBindingVerifierProvider(claims))
        listedRsa.forEach {
            val keyBindingJwt = TestVectors.vector(holderSigningKey = rsa, holderAlgorithm = it).substringAfterLast('~')
            assertThat(runBlocking { verifier.checkSignature(keyBindingJwt) }).`as`(it.name).isNotNull()
        }
        unlistedRsa.forEach {
            val keyBindingJwt = TestVectors.vector(holderSigningKey = rsa, holderAlgorithm = it).substringAfterLast('~')
            assertThat(runBlocking { verifier.checkSignature(keyBindingJwt) }).`as`(it.name).isNull()
        }
    }

    /** [compact] with the `alg` of its issuer JWT, or of its key binding JWT, replaced by [algorithm]. */
    private fun withHeaderAlgorithm(
        compact: String,
        issuerJwt: Boolean,
        algorithm: String,
    ): String {
        val parts = compact.split('~').toMutableList()
        val index = if (issuerJwt) 0 else parts.lastIndex
        val jwtParts = parts[index].split('.').toMutableList()
        val header = JSONObjectUtils.parse(Base64URL(jwtParts[0]).decodeToString()).toMutableMap()
        header["alg"] = algorithm
        jwtParts[0] = Base64URL.encode(JSONObjectUtils.toJSONString(header)).toString()
        parts[index] = jwtParts.joinToString(".")
        return parts.joinToString("~")
    }
}
