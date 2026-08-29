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
package dev.zilath.gate

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.time.Clock
import java.time.LocalDate
import java.util.Date
import java.util.UUID

/**
 * Gate-check receipts: the signed artifact the venue keeps INSTEAD of any document.
 *
 * A receipt records that a verification happened at the gate and what its outcome was —
 * never who was verified: venue, entitlement, outcome, operator, method, timestamp.
 * No name, no document number, no health data. This is by design (VARCO-40 and the
 * Garante's own pattern for the CED: verify without retaining anything about the person).
 *
 * The `method` claim is the 2027 seam: today every receipt is issued with
 * [METHOD_MANUAL_INPS_QR] (the operator checks the card and its QR on the INPS service);
 * when private relying parties can receive wallet presentations, the same receipt is
 * issued with [METHOD_WALLET_OPENID4VP] from the library's flow outcome — the venue's
 * process and records do not change.
 */
class GateReceipts(
    private val dataDir: Path,
    private val venue: String,
    private val clock: Clock,
) {
    private val signingKey: ECKey = loadOrGenerateKey()
    private val receiptsFile: Path = dataDir.resolve(RECEIPTS_FILE)
    private val verifier = ECDSAVerifier(signingKey.toECPublicKey())

    class Receipt(
        val id: String,
        val jws: String,
        val entitlement: String,
        val outcome: String,
        val operator: String,
        val issuedAt: Date,
    )

    /** Issues, signs and appends one receipt. The only write this tool ever does. */
    fun issue(
        entitlement: String,
        entitled: Boolean,
        operator: String,
        method: String = METHOD_MANUAL_INPS_QR,
    ): Receipt {
        val id = UUID.randomUUID().toString()
        val claims =
            JWTClaimsSet
                .Builder()
                .issuer(venue)
                .jwtID(id)
                .issueTime(Date.from(clock.instant()))
                .claim("venue", venue)
                .claim("entitlement", entitlement)
                .claim("outcome", if (entitled) OUTCOME_VERIFIED else OUTCOME_NOT_VERIFIED)
                .claim("entitled", entitled)
                .claim("operator", operator)
                .claim("method", method)
                .build()
        val header =
            JWSHeader
                .Builder(JWSAlgorithm.ES256)
                .keyID(signingKey.keyID)
                .type(JOSEObjectType(RECEIPT_TYP))
                .build()
        val jwt = SignedJWT(header, claims)
        jwt.sign(ECDSASigner(signingKey))
        val serialized = jwt.serialize()
        val existed = Files.exists(receiptsFile)
        Files.writeString(
            receiptsFile,
            serialized + System.lineSeparator(),
            StandardOpenOption.CREATE,
            StandardOpenOption.APPEND,
        )
        // The directory is already owner-only, so this is defence in depth — but the file
        // outlives the directory's permissions if anyone ever moves or copies it, and it
        // records who was checked at which gate and when.
        if (!existed) restrictToOwner(receiptsFile, directory = false)
        return toReceipt(jwt, serialized)
    }

    fun byId(id: String): Receipt? = all().firstOrNull { it.id == id }

    /** Receipts issued today (venue clock): what the operator sees during the event. */
    fun today(): List<Receipt> {
        val today = LocalDate.ofInstant(clock.instant(), clock.zone)
        return all().filter { LocalDate.ofInstant(it.issuedAt.toInstant(), clock.zone) == today }
    }

    /** True when the JWS really was signed by this venue's key (spot checks, audits). */
    fun verifySignature(jws: String): Boolean =
        runCatching { SignedJWT.parse(jws).verify(verifier) }.getOrDefault(false)

    /** Only receipts signed by THIS venue's key are ever loaded: a line forged into the
     *  file by anything with write access is silently excluded, never displayed. */
    private fun all(): List<Receipt> {
        if (!Files.exists(receiptsFile)) return emptyList()
        return Files
            .readAllLines(receiptsFile)
            .filter { it.isNotBlank() }
            .mapNotNull { line ->
                runCatching { SignedJWT.parse(line).takeIf { it.verify(verifier) }?.let { toReceipt(it, line) } }
                    .getOrNull()
            }
    }

    private fun toReceipt(
        jwt: SignedJWT,
        serialized: String,
    ): Receipt {
        val claims = jwt.jwtClaimsSet
        return Receipt(
            id = claims.jwtid,
            jws = serialized,
            entitlement = claims.getStringClaim("entitlement"),
            outcome = claims.getStringClaim("outcome"),
            operator = claims.getStringClaim("operator"),
            issuedAt = claims.issueTime,
        )
    }

    private fun loadOrGenerateKey(): ECKey {
        createOwnerOnlyDirectory(dataDir)
        val keyFile = dataDir.resolve(KEY_FILE)
        if (Files.exists(keyFile)) return ECKey.parse(Files.readString(keyFile))
        val key = ECKeyGenerator(Curve.P_256).keyID(KEY_ID).generate()
        // Written atomically (temp file + ATOMIC_MOVE) with owner-only permissions: the
        // private key must never be readable by other local principals, or they could
        // mint receipts this tool would accept as authentic — and a crash mid-write must
        // never leave a half-written key for the next startup to choke on.
        val temp = Files.createTempFile(dataDir, KEY_FILE, ".tmp")
        try {
            restrictToOwner(temp, directory = false)
            Files.writeString(temp, key.toJSONString())
            Files.move(temp, keyFile, StandardCopyOption.ATOMIC_MOVE)
        } finally {
            Files.deleteIfExists(temp)
        }
        return key
    }

    private fun createOwnerOnlyDirectory(dir: Path) {
        Files.createDirectories(dir)
        restrictToOwner(dir, directory = true)
    }

    /** Best effort on non-POSIX filesystems (e.g. Windows): the attribute view is absent. */
    private fun restrictToOwner(
        path: Path,
        directory: Boolean,
    ) {
        val permissions = if (directory) OWNER_ONLY_DIR else OWNER_ONLY_FILE
        runCatching {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(permissions))
        }.onFailure {
            // Silence here meant the signing key could sit with inherited permissions and
            // nobody would ever know. On a filesystem without POSIX attributes this is the
            // operator's problem to solve, but they have to be told it is theirs.
            logger.warn(
                "could not restrict permissions on {}: protect the gate data directory by other means",
                path.fileName,
            )
        }
    }

    companion object {
        private val logger = org.slf4j.LoggerFactory.getLogger(GateReceipts::class.java)

        const val RECEIPT_TYP = "zilath-gate-receipt+jwt"
        const val OUTCOME_VERIFIED = "verified"
        const val OUTCOME_NOT_VERIFIED = "not_verified"
        const val METHOD_MANUAL_INPS_QR = "manual-inps-qr"
        const val METHOD_WALLET_OPENID4VP = "wallet-openid4vp"
        private const val RECEIPTS_FILE = "gate-receipts.jsonl"
        private const val KEY_FILE = "gate-signing-key.json"
        private const val KEY_ID = "gate-signing"
        private const val OWNER_ONLY_DIR = "rwx------"
        private const val OWNER_ONLY_FILE = "rw-------"
    }
}
