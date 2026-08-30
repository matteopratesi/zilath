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
package dev.zilath.verifier.openid4vp

import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.ECDHDecrypter
import dev.zilath.verifier.core.RejectionReason
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/*
 * Response encryption (`direct_post.jwt`): what the RP advertises in its metadata and
 * the ONLY thing its response endpoint accepts back. Advertisement and enforcement read
 * the same constants so they cannot drift apart.
 */

internal const val RESPONSE_ENCRYPTION_ALG = "ECDH-ES"
internal const val RESPONSE_ENCRYPTION_ENC = "A256GCM"

/** The `enc` values the RP advertises — and the only ones the response endpoint accepts. */
internal val ACCEPTED_RESPONSE_ENCS = listOf(RESPONSE_ENCRYPTION_ENC, "A128GCM")

/** Decrypts the `direct_post.jwt` response JWE with the RP encryption key. */
internal fun decryptWalletResponse(
    jwe: String,
    config: RelyingPartyConfiguration,
): JsonObject {
    val jweObject =
        runCatching { JWEObject.parse(jwe) }
            .getOrElse { flowReject(RejectionReason.MALFORMED, "wallet response is not a JWE") }
    checkResponseEncryptionHeader(jweObject.header)
    return runCatching {
        jweObject.decrypt(ECDHDecrypter(config.keys.responseEncryptionKey))
        Json.parseToJsonElement(jweObject.payload.toString()) as JsonObject
    }.getOrElse { flowReject(RejectionReason.MALFORMED, "wallet response cannot be decrypted") }
}

/**
 * What the RP advertises is what it accepts: direct ECDH-ES with an AES-GCM content key,
 * no compression. [ECDHDecrypter] would take more — key-wrapping variants, CBC modes,
 * `zip: DEF` — and every alternative accepted here is surface the advertised metadata
 * says does not exist. Compression in particular is refused because a compressed payload
 * on an unauthenticated endpoint is a decompression bomb with a stamp on it; no wallet is
 * ever asked to compress.
 */
private fun checkResponseEncryptionHeader(header: JWEHeader) {
    if (header.algorithm?.name != RESPONSE_ENCRYPTION_ALG) {
        flowReject(RejectionReason.MALFORMED, "response JWE alg is not $RESPONSE_ENCRYPTION_ALG")
    }
    if (header.encryptionMethod?.name !in ACCEPTED_RESPONSE_ENCS) {
        flowReject(RejectionReason.MALFORMED, "response JWE enc is not an accepted method")
    }
    if (header.compressionAlgorithm != null) {
        flowReject(RejectionReason.MALFORMED, "response JWE must not be compressed")
    }
}
