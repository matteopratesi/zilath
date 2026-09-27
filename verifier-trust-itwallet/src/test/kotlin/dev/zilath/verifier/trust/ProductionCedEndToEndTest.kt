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
package dev.zilath.verifier.trust

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.ClaimPathSegment
import dev.zilath.verifier.core.IpzsFederationSnapshot
import dev.zilath.verifier.core.OAuthStatusListChecker
import dev.zilath.verifier.core.RawPresentation
import dev.zilath.verifier.core.RejectionReason
import dev.zilath.verifier.core.RequestedClaim
import dev.zilath.verifier.core.RequestedClaims
import dev.zilath.verifier.core.SdJwtVcCredentialVerifier
import dev.zilath.verifier.core.StatusListFetcher
import dev.zilath.verifier.core.TestVectors
import dev.zilath.verifier.core.VerificationContext
import dev.zilath.verifier.core.VerificationResult
import eu.europa.ec.eudi.sdjwt.DisclosableObjectSpecBuilder
import eu.europa.ec.eudi.sdjwt.cnf
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.time.Clock
import java.time.ZoneOffset
import java.util.zip.DeflaterOutputStream

/**
 * A European Disability Card shaped as IT-Wallet 1.4.6 writes it, verified from one end to
 * the other against the production federation as served on 2026-09-24.
 *
 * Before the fourth internal review 0.3.0 could verify no genuine card of this issuer: the
 * trust anchor's `metadata_policy` for `wallet_provider` was applied to an issuer that is no
 * wallet provider, and the status list token, which carries no `iss` in the IT-Wallet form,
 * was refused. Each gate has its own tests; this one runs them all together.
 *
 * The private keys of the federation are not ours, so its three documents are re-signed with
 * substitute keys under their real `kid`s, and every other claim — metadata, the anchor's
 * common policy, `constraints` — is the production one, byte for byte through a JSON round
 * trip. The trust decision itself on the untouched documents is `IpzsProductionChainTest`.
 */
class ProductionCedEndToEndTest {
    private val anchorKey: ECKey = ECKeyGenerator(Curve.P_256).keyID(TRUST_ANCHOR_KID).generate()

    /** The issuer's federation and credential key are one key in production: so here. */
    private val issuerKey: ECKey = TestVectors.issuerEcKey

    private val issuerPublishedKey: JWK =
        ECKey
            .Builder(issuerKey.toPublicJWK())
            .keyID(IpzsFederationSnapshot.CED_ISSUER_SIGNING_KID)
            .build()

    private val servedDocuments: Map<String, String> =
        IpzsFederationSnapshot.servedDocuments.mapValues { (_, document) -> resigned(document) }

    private val trustEvaluator =
        FederationTrustEvaluator(
            TrustAnchorConfig(IpzsFederationSnapshot.TRUST_ANCHOR, listOf(anchorKey.toPublicJWK())),
            { url -> servedDocuments[url] ?: throw FederationDocumentNotFoundException() },
            IpzsFederationSnapshot.clock,
        )

    private val verificationClock: Clock = Clock.fixed(TestVectors.NOW, ZoneOffset.UTC)

    @Test
    fun `a card of the production issuer shaped as IT-Wallet 1_4_6 writes it is verified`() {
        val result = verify(cardWithStatusList(), statusValue = VALID)

        assertThat(result).isInstanceOf(VerificationResult.Verified::class.java)
        val claims = (result as VerificationResult.Verified).claims.claims
        assertThat(claims.keys).containsExactlyInAnyOrder("iss", "vct", "constant_attendance_allowance")
        assertThat(claims.getValue("constant_attendance_allowance").jsonPrimitive.content).isEqualTo("true")
        assertThat(claims.getValue("vct").jsonPrimitive.content).isEqualTo(IpzsFederationSnapshot.CED_VCT)
    }

    @Test
    fun `the same card revoked in its status list is rejected as revoked`() {
        assertThat(verify(cardWithStatusList(), statusValue = INVALID))
            .isEqualTo(VerificationResult.Rejected(RejectionReason.REVOKED, "credential is revoked"))
    }

    @Test
    fun `a card whose status is only a status assertion is still rejected, and says why`() {
        val card =
            TestVectors.vectorWith(plaintextEnvelope = false, issuerTyp = "dc+sd-jwt") {
                envelope()
                objClaim("status") { objClaim("status_assertion") { claim("credential_hash_alg", "sha-256") } }
                sdClaim("constant_attendance_allowance", true)
            }
        assertThat(verify(card, statusValue = VALID))
            .isEqualTo(
                VerificationResult.Rejected(RejectionReason.STATUS_CHECK_FAILED, "status mechanism not supported"),
            )
    }

    private fun cardWithStatusList(): String =
        TestVectors.vectorWith(plaintextEnvelope = false, issuerTyp = "dc+sd-jwt") {
            envelope()
            objClaim("status") {
                objClaim("status_list") {
                    claim("idx", STATUS_INDEX)
                    claim("uri", STATUS_URI)
                }
            }
            sdClaim("given_name", "Ada")
            sdClaim("family_name", "Lovelace")
            sdClaim("birth_date", "1815-12-10")
            sdClaim("document_number", "CED-0000000")
            sdClaim("constant_attendance_allowance", true)
        }

    private fun DisclosableObjectSpecBuilder.envelope() {
        claim("iss", IpzsFederationSnapshot.CED_ISSUER)
        claim("iat", TestVectors.NOW.minusSeconds(3600).epochSecond)
        claim("exp", TestVectors.NOW.plusSeconds(365L * 24 * 3600).epochSecond)
        claim("vct", IpzsFederationSnapshot.CED_VCT)
        cnf(TestVectors.holderKey.toPublicJWK())
    }

    private fun verify(
        card: String,
        statusValue: Int,
    ): VerificationResult =
        SdJwtVcCredentialVerifier().verify(
            RawPresentation.SdJwtVcPresentation(card),
            VerificationContext(
                expectedNonce = TestVectors.NONCE,
                expectedAudiences = setOf(TestVectors.AUDIENCE),
                clock = verificationClock,
                trustEvaluator = trustEvaluator,
                statusChecker =
                    OAuthStatusListChecker(
                        StatusListFetcher { uri ->
                            check(uri == STATUS_URI) { "unexpected status list $uri" }
                            statusListToken(statusValue)
                        },
                        verificationClock,
                    ),
                expectedVcts = setOf(IpzsFederationSnapshot.CED_VCT),
                requestedClaims =
                    RequestedClaims(
                        listOf(
                            RequestedClaim(
                                listOf(ClaimPathSegment.Key("constant_attendance_allowance")),
                                values = listOf(JsonPrimitive(true)),
                            ),
                        ),
                    ),
            ),
        )

    /**
     * A Status List Token as IT-Wallet 1.4.6 §11.4.4.1.1 shows it: `typ statuslist+jwt`, `sub`,
     * `iat`, `ttl`, `status_list` with two bits per entry, and no `iss`. Signed by the issuer.
     */
    private fun statusListToken(valueAtIndex: Int): String {
        val entries = ByteArray(STATUS_LIST_BYTES)
        val entriesPerByte = Byte.SIZE_BITS / STATUS_BITS
        entries[STATUS_INDEX / entriesPerByte] =
            (valueAtIndex shl ((STATUS_INDEX % entriesPerByte) * STATUS_BITS)).toByte()
        val compressed = ByteArrayOutputStream().also { out -> DeflaterOutputStream(out).use { it.write(entries) } }
        val claims =
            JWTClaimsSet
                .Builder()
                .subject(STATUS_URI)
                .issueTime(java.util.Date.from(TestVectors.NOW.minusSeconds(600)))
                .claim("ttl", STATUS_TTL_SECONDS)
                .claim(
                    "status_list",
                    mapOf("bits" to STATUS_BITS, "lst" to Base64URL.encode(compressed.toByteArray()).toString()),
                ).build()
        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType("statuslist+jwt")).build()
        return SignedJWT(header, claims).apply { sign(ECDSASigner(issuerKey)) }.serialize()
    }

    /**
     * [document] with its keys replaced by the substitute ones under the same `kid`s, signed
     * by the substitute of the key that signed it, header kept. Nothing else is touched.
     */
    private fun resigned(document: String): String {
        val original = SignedJWT.parse(document)
        val claims = original.jwtClaimsSet.toJSONObject()
        val subject = claims["sub"]
        val issuer = claims["iss"]
        claims["jwks"] =
            jwksOf(if (subject == IpzsFederationSnapshot.TRUST_ANCHOR) anchorKey.toPublicJWK() else issuerPublishedKey)
        if (issuer == IpzsFederationSnapshot.CED_ISSUER) {
            @Suppress("UNCHECKED_CAST")
            val metadata = (claims["metadata"] as Map<String, Any?>).toMutableMap()

            @Suppress("UNCHECKED_CAST")
            val credentialIssuer = (metadata["openid_credential_issuer"] as Map<String, Any?>).toMutableMap()
            credentialIssuer["jwks"] = jwksOf(issuerPublishedKey)
            metadata["openid_credential_issuer"] = credentialIssuer
            claims["metadata"] = metadata
        }
        val signer = if (issuer == IpzsFederationSnapshot.TRUST_ANCHOR) anchorKey else issuerKey
        val header =
            JWSHeader
                .Builder(JWSAlgorithm.ES256)
                .type(original.header.type)
                .keyID(original.header.keyID)
                .build()
        return SignedJWT(header, JWTClaimsSet.parse(claims)).apply { sign(ECDSASigner(signer)) }.serialize()
    }

    private fun jwksOf(key: JWK): Map<String, Any?> = mapOf("keys" to listOf(key.toJSONObject()))

    private companion object {
        const val TRUST_ANCHOR_KID = "fU3pd1wT7bYeAZec9N1Yq4EXoX7BMkjt-m1h0hkUyBI"
        const val STATUS_URI = "https://status.example/eaa/ced/1"
        const val STATUS_INDEX = 5
        const val STATUS_BITS = 2
        const val STATUS_LIST_BYTES = 16
        const val STATUS_TTL_SECONDS = 43_200
        const val VALID = 0x00
        const val INVALID = 0x01
    }
}
