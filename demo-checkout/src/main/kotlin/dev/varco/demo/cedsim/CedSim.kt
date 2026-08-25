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
package dev.varco.demo.cedsim

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import eu.europa.ec.eudi.sdjwt.cnf
import eu.europa.ec.eudi.sdjwt.sdJwt
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock
import java.util.Date

/*
 * SIMULATED European Disability Card, for the demo only.
 *
 * The claim names mirror the PRODUCTION credential (dc_sd_jwt_EuropeanDisabilityCard,
 * vct https://ta.wallet.ipzs.it/vct/v1.0.0/europeandisabilitycard) but the vct and the
 * federation stay openly simulated: this demo must never impersonate the real issuer.
 * The DCQL asks only for the minimized subset a checkout needs — holder name, the
 * constant-attendance-allowance flag and the expiry — never portrait, birth date,
 * document number, conditions, percentages or legal subcategories.
 */
object CedSim {
    const val VCT = "urn:varco:sim:ced:1"
    const val ANCHOR_ID = "https://anchor.ced-sim.varco.invalid"
    const val ISSUER_ID = "https://issuer.ced-sim.varco.invalid"
    const val CREDENTIAL_QUERY_ID = "ced"
    val CLAIM_PATHS = listOf("given_name", "family_name", "constant_attendance_allowance", "expiry_date")

    private const val ENTITY_STATEMENT_TYP = "entity-statement+jwt"
    private const val STATEMENT_VALIDITY_SECONDS = 3600L

    /** All private keys of the simulated federation. DEMO ONLY: never handle real keys this way. */
    class Keys(
        val anchor: ECKey,
        val issuerFederation: ECKey,
        val issuerCredential: ECKey,
        val holder: ECKey,
    )

    fun generateKeys(): Keys =
        Keys(
            anchor = ECKeyGenerator(Curve.P_256).keyID("ced-sim-anchor").generate(),
            issuerFederation = ECKeyGenerator(Curve.P_256).keyID("ced-sim-issuer-fed").generate(),
            issuerCredential = ECKeyGenerator(Curve.P_256).keyID("ced-sim-issuer-cred").generate(),
            holder = ECKeyGenerator(Curve.P_256).keyID("ced-sim-holder").generate(),
        )

    fun writeKeys(
        directory: Path,
        keys: Keys,
    ) {
        Files.createDirectories(directory)
        val bundle =
            buildJsonObject {
                put("anchor", keys.anchor.toJSONString())
                put("issuerFederation", keys.issuerFederation.toJSONString())
                put("issuerCredential", keys.issuerCredential.toJSONString())
                put("holder", keys.holder.toJSONString())
            }
        Files.writeString(directory.resolve("ced-sim-keys.json"), bundle.toString())
        val anchorJwks = """{"keys":[${keys.anchor.toPublicJWK().toJSONString()}]}"""
        Files.writeString(directory.resolve("anchor-jwks.json"), anchorJwks)
    }

    fun readKeys(directory: Path): Keys {
        val bundle = JSONObjectUtils.parse(Files.readString(directory.resolve("ced-sim-keys.json")))

        fun key(name: String) = ECKey.parse(bundle[name] as String)
        return Keys(key("anchor"), key("issuerFederation"), key("issuerCredential"), key("holder"))
    }

    /** Offline trust chain: leaf entity configuration + anchor statement about the leaf. */
    fun buildTrustChain(
        keys: Keys,
        clock: Clock,
    ): List<String> {
        val leaf =
            entityStatement(keys.issuerFederation, ISSUER_ID, ISSUER_ID, clock) {
                claim("jwks", jwks(keys.issuerFederation))
                claim("authority_hints", listOf(ANCHOR_ID))
                claim(
                    "metadata",
                    mapOf("openid_credential_issuer" to mapOf("jwks" to jwks(keys.issuerCredential))),
                )
            }
        val anchorStatement =
            entityStatement(keys.anchor, ANCHOR_ID, ISSUER_ID, clock) {
                claim("jwks", jwks(keys.issuerFederation))
            }
        return listOf(leaf, anchorStatement)
    }

    /** Mints the simulated CED presentation, ready for the wallet response. */
    @Suppress("LongParameterList") // demo factory: independent, defaulted axes for tests
    fun mintPresentation(
        keys: Keys,
        nonce: String,
        audience: String,
        clock: Clock,
        constantAttendanceAllowance: Boolean = true,
        expiryDate: String = "2030-12-31",
    ): String =
        runBlocking {
            val now = clock.instant()
            val chain = buildTrustChain(keys, clock)
            val spec =
                sdJwt {
                    claim("iss", ISSUER_ID)
                    claim("iat", now.epochSecond)
                    claim("exp", now.plusSeconds(STATEMENT_VALIDITY_SECONDS).epochSecond)
                    claim("vct", VCT)
                    cnf(keys.holder.toPublicJWK())
                    sdClaim("given_name", "Maria")
                    sdClaim("family_name", "Bianchi")
                    sdClaim("constant_attendance_allowance", constantAttendanceAllowance)
                    sdClaim("expiry_date", expiryDate)
                }
            val issuer =
                NimbusSdJwtOps.issuer(
                    signer = ECDSASigner(keys.issuerCredential),
                    signAlgorithm = JWSAlgorithm.ES256,
                ) { customParam("trust_chain", chain) }
            val issued = issuer.issue(spec).getOrThrow()
            val kbJwt =
                NimbusSdJwtOps.kbJwtIssuer(
                    ECDSASigner(keys.holder),
                    JWSAlgorithm.ES256,
                    keys.holder.toPublicJWK(),
                ) {
                    audience(audience)
                    claim("nonce", nonce)
                    issueTime(Date.from(now))
                }
            with(NimbusSdJwtOps) { issued.serializeWithKeyBinding(kbJwt) }.getOrThrow()
        }

    /** Wraps the presentation in the encrypted `direct_post.jwt` response body. */
    fun buildEncryptedResponse(
        state: String,
        presentation: String,
        encryptionKey: JWK,
    ): String {
        val payload =
            buildJsonObject {
                put(
                    "vp_token",
                    buildJsonObject {
                        put(
                            CREDENTIAL_QUERY_ID,
                            buildJsonArray { add(kotlinx.serialization.json.JsonPrimitive(presentation)) },
                        )
                    },
                )
                put("state", state)
            }
        val jwe = JWEObject(JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM), Payload(payload.toString()))
        jwe.encrypt(ECDHEncrypter(encryptionKey.toECKey()))
        return jwe.serialize()
    }

    /**
     * Checkout policy for the simulated CED: the DCQL only asks for DISCLOSURE of the
     * claims — enforcing their values is the relying party's job. The ticket is granted
     * only for an entitled, non-expired card.
     */
    fun entitlementGranted(
        claims: kotlinx.serialization.json.JsonObject,
        clock: Clock,
    ): Boolean {
        // A JSON Boolean is required: the string "true" must not grant anything.
        val entitledPrimitive = claims["constant_attendance_allowance"] as? JsonPrimitive
        val entitled =
            entitledPrimitive != null &&
                !entitledPrimitive.isString &&
                entitledPrimitive.booleanOrNull == true
        val expiry =
            runCatching {
                java.time.LocalDate.parse(
                    (claims["expiry_date"] as? kotlinx.serialization.json.JsonPrimitive)?.content,
                )
            }.getOrNull() ?: return false
        val today = java.time.LocalDate.ofInstant(clock.instant(), java.time.ZoneOffset.UTC)
        return entitled && !expiry.isBefore(today)
    }

    private fun jwks(key: ECKey): Map<String, Any> = mapOf("keys" to listOf(key.toPublicJWK().toJSONObject()))

    private fun entityStatement(
        signer: ECKey,
        iss: String,
        sub: String,
        clock: Clock,
        configure: JWTClaimsSet.Builder.() -> Unit,
    ): String {
        val now = clock.instant()
        val claims =
            JWTClaimsSet
                .Builder()
                .issuer(iss)
                .subject(sub)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(STATEMENT_VALIDITY_SECONDS)))
                .apply(configure)
                .build()
        val jwt =
            SignedJWT(
                JWSHeader
                    .Builder(JWSAlgorithm.ES256)
                    .keyID(signer.keyID)
                    .type(JOSEObjectType(ENTITY_STATEMENT_TYP))
                    .build(),
                claims,
            )
        jwt.sign(ECDSASigner(signer))
        return jwt.serialize()
    }
}
