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
package dev.varco.verifier.core

import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.SignedJWT
import java.util.zip.Inflater

/** Retrieves a status list token from its URI; injectable so tests stay offline. */
fun interface StatusListFetcher {
    fun fetch(uri: String): String
}

/**
 * [StatusChecker] backed by an OAuth Status List token (draft-ietf-oauth-status-list):
 * a JWT whose `status_list` claim carries a zlib-compressed bit array where each
 * credential occupies `bits` bits at its `idx` position; 0 means valid.
 *
 * NOTE (plan docs/03 §5-M0.2): the status list token signature is NOT verified here —
 * trusting the status provider requires the IT-Wallet trust chain, which lands in M0.4.
 * Any fetch or parsing failure degrades to [CredentialStatus.UNKNOWN], never to valid.
 */
class OAuthStatusListChecker(
    private val fetcher: StatusListFetcher,
) : StatusChecker {
    override fun check(statusRef: StatusReference): CredentialStatus =
        runCatching { lookup(statusRef) }.getOrDefault(CredentialStatus.UNKNOWN)

    private fun lookup(statusRef: StatusReference): CredentialStatus {
        val token = fetcher.fetch(statusRef.uri)
        val statusList =
            checkNotNull(SignedJWT.parse(token).jwtClaimsSet.getJSONObjectClaim("status_list")) {
                "token has no status_list claim"
            }
        val bits = (statusList["bits"] as Number).toInt()
        require(bits in VALID_BITS_SIZES) { "unsupported bits size: $bits" }
        val compressed = Base64URL.from(statusList["lst"] as String).decode()
        val value = statusValueAt(inflate(compressed), bits, statusRef.index)
        return if (value == 0) CredentialStatus.VALID else CredentialStatus.REVOKED
    }

    private fun statusValueAt(
        bytes: ByteArray,
        bits: Int,
        index: Int,
    ): Int {
        val entriesPerByte = BITS_PER_BYTE / bits
        val byteIndex = index / entriesPerByte
        require(byteIndex in bytes.indices) { "index $index outside the status list" }
        val shift = (index % entriesPerByte) * bits
        val mask = (1 shl bits) - 1
        return (bytes[byteIndex].toInt() shr shift) and mask
    }

    private fun inflate(compressed: ByteArray): ByteArray {
        val inflater = Inflater()
        return try {
            inflater.setInput(compressed)
            val buffer = ByteArray(INFLATE_BUFFER_SIZE)
            val output = java.io.ByteArrayOutputStream()
            while (!inflater.finished()) {
                val produced = inflater.inflate(buffer)
                check(produced > 0 || inflater.finished()) { "truncated status list" }
                output.write(buffer, 0, produced)
                // The token comes from a remote, not-yet-trusted source: cap the expansion
                // so a small zlib payload cannot exhaust the heap (zip bomb).
                check(output.size() <= MAX_INFLATED_SIZE) { "status list larger than $MAX_INFLATED_SIZE bytes" }
            }
            output.toByteArray()
        } finally {
            inflater.end()
        }
    }

    companion object {
        private const val BITS_PER_BYTE = 8
        private const val INFLATE_BUFFER_SIZE = 4096

        /** 1 MiB holds 8.4M single-bit entries: far above any realistic status list. */
        private const val MAX_INFLATED_SIZE = 1 shl 20
        private val VALID_BITS_SIZES = setOf(1, 2, 4, 8)
    }
}
