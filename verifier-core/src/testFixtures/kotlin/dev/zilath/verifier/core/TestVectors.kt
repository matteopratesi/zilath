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
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import eu.europa.ec.eudi.sdjwt.cnf
import eu.europa.ec.eudi.sdjwt.sdJwt
import kotlinx.coroutines.runBlocking
import java.time.Instant
import java.util.Date

/**
 * Generates SD-JWT VC test vectors with ephemeral keys, using the same EUDI library
 * on the issuance side (plan docs/03 §5-M0.2).
 */
object TestVectors {
    val NOW: Instant = Instant.parse("2026-08-24T10:00:00Z")
    const val NONCE = "test-nonce-1234"
    const val AUDIENCE = "https://verifier.example/zilath"
    const val ISSUER = "https://issuer.example"

    const val VCT = "urn:zilath:test:entitlement"

    val issuerEcKey = ECKeyGenerator(Curve.P_256).keyID("issuer-ec").generate()
    val issuerRsaKey = RSAKeyGenerator(RSA_KEY_SIZE).keyID("issuer-rsa").generate()
    val holderKey = ECKeyGenerator(Curve.P_256).keyID("holder").generate()

    fun trustIssuerEc(): TrustEvaluator = TrustEvaluator { TrustDecision.Trusted(listOf(issuerEcKey.toPublicJWK())) }

    fun trustIssuerRsa(): TrustEvaluator = TrustEvaluator { TrustDecision.Trusted(listOf(issuerRsaKey.toPublicJWK())) }

    @Suppress("LongParameterList") // test-vector factory: every parameter is an independent, defaulted axis
    fun vector(
        iat: Instant = NOW.minusSeconds(600),
        exp: Instant = NOW.plusSeconds(3600),
        nbf: Instant? = null,
        kbIssuedAt: Instant = NOW,
        nonce: String = NONCE,
        audience: String = AUDIENCE,
        includeCnf: Boolean = true,
        statusUri: String? = null,
        statusIndex: Int? = null,
        useRsaIssuer: Boolean = false,
        vct: String = VCT,
        statusNotAnObject: Boolean = false,
    ): String =
        runBlocking {
            val spec =
                sdJwt {
                    claim("iss", ISSUER)
                    claim("iat", iat.epochSecond)
                    claim("exp", exp.epochSecond)
                    if (nbf != null) claim("nbf", nbf.epochSecond)
                    claim("vct", vct)
                    if (includeCnf) cnf(holderKey.toPublicJWK())
                    if (statusNotAnObject) claim("status", "not-an-object")
                    if (statusUri != null && statusIndex != null) {
                        objClaim("status") {
                            objClaim("status_list") {
                                claim("idx", statusIndex)
                                claim("uri", statusUri)
                            }
                        }
                    }
                    sdClaim("given_name", "Ada")
                    sdClaim("family_name", "Lovelace")
                    sdClaim("entitled", true)
                }
            val issuer =
                if (useRsaIssuer) {
                    NimbusSdJwtOps.issuer(signer = RSASSASigner(issuerRsaKey), signAlgorithm = JWSAlgorithm.RS256)
                } else {
                    NimbusSdJwtOps.issuer(signer = ECDSASigner(issuerEcKey), signAlgorithm = JWSAlgorithm.ES256)
                }
            val issued = issuer.issue(spec).getOrThrow()
            val kbJwtBuilder =
                NimbusSdJwtOps.kbJwtIssuer(
                    ECDSASigner(holderKey),
                    JWSAlgorithm.ES256,
                    holderKey.toPublicJWK(),
                ) {
                    audience(audience)
                    claim("nonce", nonce)
                    issueTime(Date.from(kbIssuedAt))
                }
            with(NimbusSdJwtOps) { issued.serializeWithKeyBinding(kbJwtBuilder) }.getOrThrow()
        }

    /** Flips one character of a base64url segment so the content no longer matches. */
    fun flipChar(
        segment: String,
        position: Int = segment.length / 2,
    ): String {
        val replacement = if (segment[position] != 'A') 'A' else 'B'
        return segment.replaceRange(position, position + 1, replacement.toString())
    }

    fun withTamperedIssuerSignature(compact: String): String {
        val parts = compact.split('~').toMutableList()
        val jwtParts = parts.first().split('.').toMutableList()
        jwtParts[2] = flipChar(jwtParts[2])
        parts[0] = jwtParts.joinToString(".")
        return parts.joinToString("~")
    }

    fun withTamperedDisclosure(compact: String): String {
        val parts = compact.split('~').toMutableList()
        check(parts.size > 2) { "vector has no disclosures" }
        parts[1] = flipChar(parts[1])
        return parts.joinToString("~")
    }

    fun withTamperedKeyBindingSignature(compact: String): String {
        val parts = compact.split('~').toMutableList()
        val kbParts = parts.last().split('.').toMutableList()
        kbParts[2] = flipChar(kbParts[2])
        parts[parts.lastIndex] = kbParts.joinToString(".")
        return parts.joinToString("~")
    }

    private const val RSA_KEY_SIZE = 2048
}
