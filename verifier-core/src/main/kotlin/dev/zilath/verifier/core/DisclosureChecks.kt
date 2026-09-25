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

import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.Disclosure
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import eu.europa.ec.eudi.sdjwt.SdJwt
import eu.europa.ec.eudi.sdjwt.vc.ClaimPathElement
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.io.encoding.Base64

/*
 * What the disclosures of a verified SD-JWT may and may not say, beyond matching their
 * digests: checked after the EUDI library has matched them and before anything reads the
 * recreated claims.
 */

/**
 * A concrete path into the recreated claims — object member names and array indices,
 * never [ClaimPathSegment.AllElements].
 */
internal typealias ConcretePath = List<ClaimPathSegment>

/**
 * The claims of a verified SD-JWT with its selective disclosures resolved, and which of
 * their paths the holder revealed: a path is in [disclosedPaths] when a disclosure put it
 * there, itself or through one of its ancestors. Every other path is issuer plaintext.
 */
internal class RecreatedClaims(
    val claims: JsonObject,
    val disclosedPaths: Set<ConcretePath>,
)

/**
 * RFC 9901 §4.2.1: a disclosed claim name MUST be a string and MUST NOT be `_sd` or `...`
 * (§7.1 step 3.c.ii.2: otherwise the SD-JWT MUST be rejected). The EUDI library enforces
 * this when issuing, not when verifying: it reads the name with `jsonPrimitive.content`,
 * so `5` became a claim named "5" and `null` one named "null", and a claim named `...`
 * reached the application (fourth internal review). Only the issuer can produce these —
 * the digest is signed — but the rule is the verifier's too, and it is checked here on the
 * disclosure as it travels, independently of what any version of the library tolerates.
 */
internal fun checkDisclosureNames(disclosures: List<Disclosure>) {
    for (disclosure in disclosures) {
        if (disclosure !is Disclosure.ObjectProperty) continue
        val decoded =
            runCatching { Json.parseToJsonElement(DISCLOSURE_BASE64.decode(disclosure.value).decodeToString()) }
                .getOrNull()
        val name = ((decoded as? JsonArray)?.getOrNull(1) as? JsonPrimitive)?.takeIf { it.isString }?.content
        if (name == null || name in RESERVED_CLAIM_NAMES) {
            reject(RejectionReason.DISCLOSURE_TAMPERED, "a disclosure does not name a valid claim")
        }
    }
}

/**
 * Resolves the disclosures of [sdJwt], and records which paths they revealed.
 *
 * Wrapped because the library throws on shapes a trusted issuer can still sign: `_sd` that
 * is not an array, a disclosure whose name collides with a plaintext claim, an array
 * element disclosure referenced from `_sd`. [CredentialVerifier.verify] promises to throw
 * only when the pipeline itself breaks; before the fourth internal review these
 * exceptions escaped it. The library's message is not carried over: see [rejectionOf].
 */
internal fun recreateClaimsOf(sdJwt: SdJwt<SignedJWT>): RecreatedClaims {
    val (claims, disclosuresPerPath) =
        runCatching { with(NimbusSdJwtOps) { sdJwt.recreateClaimsAndDisclosuresPerClaim() } }
            .getOrElse {
                reject(
                    RejectionReason.DISCLOSURE_TAMPERED,
                    "disclosures cannot be applied to the credential",
                )
            }
    val disclosed =
        disclosuresPerPath
            .filterValues { it.isNotEmpty() }
            .keys
            .map { path -> path.value.map(::segmentOf) }
            .toSet()
    return RecreatedClaims(claims, disclosed)
}

/**
 * SD-JWT VC (draft-ietf-oauth-sd-jwt-vc §3.2.2.2): `iss`, `nbf`, `exp`, `cnf`, `vct`,
 * `vct#integrity` and `status` MUST NOT be selectively disclosed. Every security check of
 * the pipeline reads them from the signed payload, where a selectively disclosed claim is
 * only a digest: a `status` behind a disclosure skipped the revocation check, an `exp`
 * behind one the expiry, whether the holder presented the disclosure or withheld it
 * (fourth internal review). The duty is the issuer's; the verifier refuses to be the one
 * that pays for a non-conformant issuer. A withheld disclosure cannot be recognised — a
 * digest is opaque — but a credential without a plaintext `exp` is already refused, and a
 * disclosure for any of these names, at any depth below them, is refused here. `_sd_alg`
 * is the SD-JWT machinery itself (RFC 9901 §4.1.1) and joins them.
 */
internal fun checkEnvelopeIsPlaintext(recreated: RecreatedClaims) {
    val disclosedEnvelope =
        recreated.disclosedPaths.any { path ->
            (path.firstOrNull() as? ClaimPathSegment.Key)?.name in PLAINTEXT_ONLY_CLAIMS
        }
    if (disclosedEnvelope) {
        reject(RejectionReason.MALFORMED, "a claim that must be in plaintext is selectively disclosed")
    }
}

private fun segmentOf(element: ClaimPathElement): ClaimPathSegment =
    when (element) {
        is ClaimPathElement.Claim -> ClaimPathSegment.Key(element.name)
        is ClaimPathElement.ArrayElement -> ClaimPathSegment.Index(element.index)
        ClaimPathElement.AllArrayElements -> ClaimPathSegment.AllElements
    }

private val RESERVED_CLAIM_NAMES = setOf("_sd", "...")

private val PLAINTEXT_ONLY_CLAIMS = setOf("iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "status", "_sd_alg")

/** The decoder `eudi-lib-jvm-sdjwt-kt` reads disclosures with (its `Base64UrlNoPadding`). */
internal val DISCLOSURE_BASE64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)
