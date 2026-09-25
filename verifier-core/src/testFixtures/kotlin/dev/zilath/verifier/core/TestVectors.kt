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
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.opts.AllowWeakRSAKey
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.util.Base64URL
import eu.europa.ec.eudi.sdjwt.DisclosableObjectSpecBuilder
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import eu.europa.ec.eudi.sdjwt.SdJwt
import eu.europa.ec.eudi.sdjwt.SdJwtFactory
import eu.europa.ec.eudi.sdjwt.cnf
import eu.europa.ec.eudi.sdjwt.sdJwt
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonArray
import java.security.MessageDigest
import java.time.Instant

/**
 * Generates SD-JWT VC test vectors with ephemeral keys, using the same EUDI library
 * on the issuance side.
 *
 * The key binding JWT is signed here rather than by the EUDI helper, and its `sd_hash`
 * computed here too (RFC 9901 §4.3): an oracle independent of the code under test, and
 * the only way to present the header forms and raw claim values the verifier must refuse.
 */
object TestVectors {
    val NOW: Instant = Instant.parse("2026-08-24T10:00:00Z")
    const val NONCE = "test-nonce-1234"
    const val AUDIENCE = "https://verifier.example/zilath"
    const val ISSUER = "https://issuer.example"

    const val VCT = "urn:zilath:test:entitlement"

    /** The `_sd_alg` the EUDI factory uses unless told otherwise, and the one IT-Wallet issuers use. */
    const val SHA_256 = "sha-256"

    /** RFC 9901 §4.3: the only `typ` a key binding JWT may carry. */
    const val KB_TYP = "kb+jwt"

    val issuerEcKey = ECKeyGenerator(Curve.P_256).keyID("issuer-ec").generate()
    val issuerRsaKey = RSAKeyGenerator(RSA_KEY_SIZE).keyID("issuer-rsa").generate()
    val holderKey = ECKeyGenerator(Curve.P_256).keyID("holder").generate()

    fun trustIssuerEc(): TrustEvaluator = TrustEvaluator { TrustDecision.Trusted(listOf(issuerEcKey.toPublicJWK())) }

    fun trustIssuerRsa(): TrustEvaluator = TrustEvaluator { TrustDecision.Trusted(listOf(issuerRsaKey.toPublicJWK())) }

    /** Trusts exactly the public half of [key], whatever its type or size. */
    fun trustIssuer(key: JWK): TrustEvaluator = TrustEvaluator { TrustDecision.Trusted(listOf(key.toPublicJWK())) }

    /**
     * A presentation disclosing `given_name`, `family_name` and `entitled`, with everything
     * else in plaintext. Every parameter is an independent axis with a default that gives
     * a presentation [SdJwtVcCredentialVerifier] accepts.
     *
     * @param exp null omits the claim.
     * @param sdAlg the `_sd_alg` the credential is issued with (`sha-256`, `sha-384`, ...).
     * @param issuerTyp the issuer JWT `typ` header; null omits it.
     * @param issuerHeaderParams extra issuer JWT header parameters, such as `trust_chain`.
     * @param issuerSigningKey signs the issuer JWT instead of [issuerEcKey] or [issuerRsaKey];
     *   RSA keys below 2048 bits are allowed here, which is the point of passing one.
     * @param holderSigningKey the holder key put in `cnf` and signing the key binding.
     * @param kbTyp the key binding `typ` header; null omits it.
     * @param kbAudiences the key binding `aud` as a JSON array, instead of [audience] as a string.
     * @param kbIssuedAtEpochSecond the key binding `iat` verbatim, instead of [kbIssuedAt].
     * @param kbSdHashAlg the algorithm the key binding `sd_hash` is computed with, when it
     *   must differ from [sdAlg].
     */
    @Suppress("LongParameterList") // test-vector factory: every parameter is an independent, defaulted axis
    fun vector(
        iat: Instant = NOW.minusSeconds(600),
        exp: Instant? = NOW.plusSeconds(3600),
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
        sdAlg: String = SHA_256,
        issuerTyp: String? = null,
        issuerHeaderParams: Map<String, Any> = emptyMap(),
        issuerSigningKey: JWK? = null,
        holderSigningKey: JWK? = null,
        kbTyp: String? = KB_TYP,
        kbAudiences: List<String>? = null,
        kbIssuedAtEpochSecond: Long? = null,
        kbSdHashAlg: String? = null,
    ): String {
        val holder = holderSigningKey ?: holderKey
        val envelope =
            Envelope(
                iat = iat,
                exp = exp,
                nbf = nbf,
                vct = vct,
                holder = holder.takeIf { includeCnf },
            )
        val issuance =
            Issuance(
                sdAlg = sdAlg,
                typ = issuerTyp,
                headerParams = issuerHeaderParams,
                signingKey = issuerSigningKey ?: if (useRsaIssuer) issuerRsaKey else issuerEcKey,
            )
        val binding =
            Binding(
                holder = holder,
                nonce = nonce,
                audience = kbAudiences ?: audience,
                issuedAt = kbIssuedAtEpochSecond ?: kbIssuedAt.epochSecond,
                typ = kbTyp,
                sdHashAlg = kbSdHashAlg ?: sdAlg,
            )
        return present(issuance, envelope, binding, { true }) {
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
    }

    /**
     * A presentation of a credential whose non-envelope claims are [claims], in the EUDI
     * issuance DSL, disclosing only the disclosures [disclose] keeps — each is handed over
     * decoded, `[salt, name, value]` or `[salt, value]`. The envelope (`iss`, `iat`, `exp`,
     * `vct`, `cnf`) is plaintext unless [plaintextEnvelope] is false, when [claims] must
     * write it.
     */
    fun vectorWith(
        disclose: (JsonArray) -> Boolean = { true },
        plaintextEnvelope: Boolean = true,
        claims: DisclosableObjectSpecBuilder.() -> Unit,
    ): String {
        val envelope = Envelope(holder = holderKey).takeIf { plaintextEnvelope } ?: Envelope(written = false)
        return present(Issuance(), envelope, Binding(), disclose, claims)
    }

    /**
     * A presentation built by hand, byte by byte, for the shapes an honest issuance library
     * refuses to produce: a disclosure named `...`, `_sd` that is not an array, nesting no
     * issuer would use, a date no Nimbus-based issuer can write (the EUDI issuer passes the
     * payload through `JWTClaimsSet`, whose `Date` conversion rewrites `exp` and truncates
     * fractions). [disclosures] are the JSON texts of the disclosures, in order; their
     * digests go into the top-level `_sd` unless [referenced] is false or [payload] sets
     * `_sd` itself. [payload] replaces or extends the plaintext envelope, [omitted] names
     * envelope claims to leave out, and the result is signed by [issuerEcKey] as written.
     */
    fun handMade(
        payload: Map<String, Any?> = emptyMap(),
        disclosures: List<String> = emptyList(),
        referenced: Boolean = true,
        omitted: Set<String> = emptySet(),
    ): String {
        val encoded = disclosures.map(::encodeDisclosure)
        val claims =
            linkedMapOf<String, Any?>(
                "iss" to ISSUER,
                "iat" to NOW.minusSeconds(600).epochSecond,
                "exp" to NOW.plusSeconds(3600).epochSecond,
                "vct" to VCT,
                "cnf" to mapOf("jwk" to holderKey.toPublicJWK().toJSONObject()),
                "_sd_alg" to SHA_256,
            )
        if (referenced) claims["_sd"] = encoded.map(::digestOf)
        claims.putAll(payload)
        omitted.forEach(claims::remove)
        val issuerJwt = signed(JWSHeader.Builder(JWSAlgorithm.ES256).build(), claims, issuerEcKey)
        val presented = encoded.fold("$issuerJwt~") { acc, disclosure -> "$acc$disclosure~" }
        return presented + keyBindingJwt(presented, Binding())
    }

    /** Base64url of a disclosure's JSON text, as it travels. */
    fun encodeDisclosure(json: String): String = Base64URL.encode(json.toByteArray(Charsets.UTF_8)).toString()

    /** The SHA-256 digest an issuer puts in `_sd` for [disclosure] (RFC 9901 §4.2.3). */
    fun digestOf(disclosure: String): String = hashOf(disclosure, SHA_256)

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

    /** The plaintext claims every credential carries; [written] false leaves them to the caller. */
    private data class Envelope(
        val iat: Instant = NOW.minusSeconds(600),
        val exp: Instant? = NOW.plusSeconds(3600),
        val nbf: Instant? = null,
        val vct: String = VCT,
        val holder: JWK? = holderKey,
        val written: Boolean = true,
    )

    private data class Issuance(
        val sdAlg: String = SHA_256,
        val typ: String? = null,
        val headerParams: Map<String, Any> = emptyMap(),
        val signingKey: JWK = issuerEcKey,
    )

    private data class Binding(
        val holder: JWK = holderKey,
        val nonce: String = NONCE,
        /** A String is written as a string, a List as a JSON array. */
        val audience: Any = AUDIENCE,
        val issuedAt: Long = NOW.epochSecond,
        val typ: String? = KB_TYP,
        val sdHashAlg: String = SHA_256,
    )

    private fun present(
        issuance: Issuance,
        envelope: Envelope,
        binding: Binding,
        disclose: (JsonArray) -> Boolean,
        claims: DisclosableObjectSpecBuilder.() -> Unit,
    ): String =
        runBlocking {
            val spec =
                sdJwt {
                    if (envelope.written) {
                        claim("iss", ISSUER)
                        claim("iat", envelope.iat.epochSecond)
                        envelope.exp?.let { claim("exp", it.epochSecond) }
                        envelope.nbf?.let { claim("nbf", it.epochSecond) }
                        claim("vct", envelope.vct)
                        envelope.holder?.let { cnf(it.toPublicJWK()) }
                    }
                    claims()
                }
            val factory = SdJwtFactory(hashAlgorithm = checkNotNull(HashAlgorithm.fromString(issuance.sdAlg)))
            val key = issuance.signingKey
            val issued =
                NimbusSdJwtOps
                    .issuer(factory, signerFor(key), algorithmFor(key)) {
                        issuance.typ?.let { type(JOSEObjectType(it)) }
                        issuance.headerParams.forEach { (name, value) -> customParam(name, value) }
                    }.issue(spec)
                    .getOrThrow()
            val kept = issued.disclosures.filter { disclose(decoded(it.value)) }
            val presented = with(NimbusSdJwtOps) { SdJwt(issued.jwt, kept).serialize() }
            presented + keyBindingJwt(presented, binding)
        }

    /**
     * The key binding JWT over [presented] (`issuer-jwt~d1~...~`), with its claims written
     * as raw JSON so that an array audience stays an array and an `iat` stays the number given.
     */
    private fun keyBindingJwt(
        presented: String,
        binding: Binding,
    ): String {
        val header =
            JWSHeader
                .Builder(algorithmFor(binding.holder))
                .apply {
                    binding.typ?.let { type(JOSEObjectType(it)) }
                    keyID(binding.holder.keyID)
                }.build()
        val claims =
            linkedMapOf(
                "aud" to binding.audience,
                "nonce" to binding.nonce,
                "iat" to binding.issuedAt,
                "sd_hash" to hashOf(presented, binding.sdHashAlg),
            )
        return signed(header, claims, binding.holder)
    }

    private fun signed(
        header: JWSHeader,
        claims: Map<String, Any?>,
        key: JWK,
    ): String = JWSObject(header, Payload(claims)).apply { sign(signerFor(key)) }.serialize()

    private fun decoded(disclosure: String): JsonArray =
        Json.parseToJsonElement(Base64URL(disclosure).decodeToString()).jsonArray

    private fun hashOf(
        text: String,
        sdAlg: String,
    ): String {
        val algorithm = checkNotNull(JAVA_DIGESTS[sdAlg]) { "no digest for $sdAlg" }
        val digest = MessageDigest.getInstance(algorithm).digest(text.toByteArray(Charsets.US_ASCII))
        return Base64URL.encode(digest).toString()
    }

    private fun signerFor(key: JWK): JWSSigner =
        when (key.keyType) {
            KeyType.EC -> ECDSASigner(key.toECKey())
            KeyType.RSA -> RSASSASigner(key.toRSAKey().toRSAPrivateKey(), setOf(AllowWeakRSAKey.getInstance()))
            else -> error("unsupported test key type ${key.keyType}")
        }

    private fun algorithmFor(key: JWK): JWSAlgorithm =
        when (key.keyType) {
            KeyType.EC ->
                when (key.toECKey().curve) {
                    Curve.P_384 -> JWSAlgorithm.ES384
                    Curve.P_521 -> JWSAlgorithm.ES512
                    else -> JWSAlgorithm.ES256
                }
            else -> JWSAlgorithm.RS256
        }

    private val JAVA_DIGESTS = mapOf(SHA_256 to "SHA-256", "sha-384" to "SHA-384", "sha-512" to "SHA-512")

    private const val RSA_KEY_SIZE = 2048
}
