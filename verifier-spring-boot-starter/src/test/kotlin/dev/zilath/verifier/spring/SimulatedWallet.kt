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
package dev.zilath.verifier.spring

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.CredentialVerifier
import dev.zilath.verifier.core.RawPresentation
import dev.zilath.verifier.core.RejectionReason
import dev.zilath.verifier.core.VerificationContext
import dev.zilath.verifier.core.VerificationResult
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * The `response` a wallet posts for the transaction of [requestObject]: a vp_token for the
 * `pid` query and the transaction's `state`, encrypted to the key the request object
 * publishes. The presentation is a placeholder: the tests that post it choose the verdict
 * with a [ScriptedVerifier].
 */
internal fun encryptedResponseFor(requestObject: String): String {
    val claims = SignedJWT.parse(requestObject).jwtClaimsSet
    val jwks = claims.getJSONObjectClaim("client_metadata")["jwks"] as Map<*, *>

    @Suppress("UNCHECKED_CAST")
    val key = JWK.parse(JSONObjectUtils.toJSONString((jwks["keys"] as List<*>).first() as Map<String, Any?>))
    val payload =
        buildJsonObject {
            put("vp_token", buildJsonObject { put("pid", buildJsonArray { add("placeholder~") }) })
            put("state", claims.getStringClaim("state"))
        }
    val jwe = JWEObject(JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM), Payload(payload.toString()))
    jwe.encrypt(ECDHEncrypter(key.toECKey()))
    return jwe.serialize()
}

/** A verifier whose next verdict the test sets: what the endpoint does with each one is the point. */
class ScriptedVerifier : CredentialVerifier {
    @Volatile
    var next: VerificationResult = VerificationResult.Rejected(RejectionReason.MALFORMED)

    override fun verify(
        presentation: RawPresentation,
        ctx: VerificationContext,
    ): VerificationResult = next
}
