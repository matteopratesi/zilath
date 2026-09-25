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

/**
 * How large a presentation may be before any of it is parsed: the first thing
 * [SdJwtVcCredentialVerifier] checks, ahead of the trust decision and the signatures.
 *
 * The fourth internal review found nothing at all between the wallet's string and the
 * JSON parser of the disclosures: twelve megabytes of decoy disclosures verified, and a
 * single disclosure nested a hundred thousand levels deep, under a digest a trusted issuer
 * had signed, exhausted the heap — about a kilobyte of heap per level, from an endpoint
 * anyone holding a transaction id can post to. The issuer JWT and the key binding go
 * through Nimbus, which bounds nesting; the disclosures go through kotlinx.serialization,
 * which does not.
 *
 * The defaults are far above any real credential. A disability card discloses eight claims
 * and a PID a few dozen at most; the largest single thing a credential carries is its
 * portrait, tens of kilobytes; real claims nest three to six levels (an address, a list of
 * driving privileges with their codes). The issuer JWT header, the other large part, cannot
 * exceed Nimbus's 20,000 characters anyway (see `parseIssuerJwt`).
 */
data class PresentationLimits(
    /** Characters of the compact serialization, `issuer-jwt~d1~...~kb-jwt`, as received. */
    val maxLength: Int = DEFAULT_MAX_LENGTH,
    /** Disclosures in one presentation. */
    val maxDisclosures: Int = DEFAULT_MAX_DISCLOSURES,
    /** JSON nesting of one decoded disclosure, counting the disclosure's own array as 1. */
    val maxDisclosureDepth: Int = DEFAULT_MAX_DISCLOSURE_DEPTH,
) {
    init {
        require(maxLength > 0) { "maxLength must be positive" }
        require(maxDisclosures >= 0) { "maxDisclosures must not be negative" }
        require(maxDisclosureDepth > 0) { "maxDisclosureDepth must be positive" }
    }

    companion object {
        /** 1 MiB: a portrait of several hundred kilobytes still fits, base64url twice over. */
        const val DEFAULT_MAX_LENGTH: Int = 1 shl 20
        const val DEFAULT_MAX_DISCLOSURES: Int = 256
        const val DEFAULT_MAX_DISCLOSURE_DEPTH: Int = 32
    }
}

/**
 * Enforces [limits] on [compact] without parsing it: its length, the number of `~`
 * separated disclosures, and the nesting of each disclosure, measured on its decoded bytes.
 *
 * The bytes are exactly those the EUDI library will parse, decoded with the same base64url
 * decoder (url-safe alphabet, no padding). A disclosure that decoder refuses would be
 * refused by EUDI too, so it is refused here as tampered — rather than skipped, which would
 * let a reading the scan does not share reach the parser unmeasured.
 */
internal fun checkPresentationLimits(
    compact: String,
    limits: PresentationLimits,
) {
    if (compact.length > limits.maxLength) {
        reject(RejectionReason.MALFORMED, "presentation exceeds the size limit")
    }
    val segments = compact.split(TILDE)
    // issuer-jwt ~ d1 ~ ... ~ dn ~ kb-jwt: the disclosures are everything in between.
    val disclosures = if (segments.size > 2) segments.subList(1, segments.lastIndex) else emptyList()
    if (disclosures.size > limits.maxDisclosures) {
        reject(RejectionReason.MALFORMED, "presentation has too many disclosures")
    }
    for (disclosure in disclosures) {
        val bytes =
            runCatching { DISCLOSURE_BASE64.decode(disclosure) }
                .getOrElse { reject(RejectionReason.DISCLOSURE_TAMPERED, "disclosures do not match the credential") }
        if (jsonDepthExceeds(bytes, limits.maxDisclosureDepth)) {
            reject(RejectionReason.MALFORMED, "a disclosure is nested too deeply")
        }
    }
}

/**
 * True when the JSON text in [bytes] has more than [max] arrays or objects open at once.
 * Bytes, not characters: in UTF-8 every structural character is a single byte below 0x80
 * that never occurs inside a multi-byte sequence, so no decoding choice can hide one.
 */
private fun jsonDepthExceeds(
    bytes: ByteArray,
    max: Int,
): Boolean {
    var depth = 0
    var inString = false
    var escaped = false
    for (byte in bytes) {
        val c = byte.toInt().toChar()
        when {
            escaped -> escaped = false
            inString && c == '\\' -> escaped = true
            c == '"' -> inString = !inString
            inString -> Unit
            c == '[' || c == '{' -> if (++depth > max) return true
            c == ']' || c == '}' -> depth--
        }
    }
    return false
}
