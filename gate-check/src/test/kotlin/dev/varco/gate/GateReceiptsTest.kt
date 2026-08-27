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
package dev.varco.gate

import com.nimbusds.jwt.SignedJWT
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class GateReceiptsTest {
    private val clock = Clock.fixed(Instant.parse("2026-08-27T19:30:00Z"), ZoneOffset.UTC)

    @Test
    fun `a receipt records outcome and context but never the person`(
        @TempDir dir: Path,
    ) {
        val receipts = GateReceipts(dir, "Teatro di Prova", clock)
        val receipt = receipts.issue("Biglietto accompagnatore", entitled = true, operator = "MP")
        val claims = SignedJWT.parse(receipt.jws).jwtClaimsSet
        assertThat(claims.getStringClaim("venue")).isEqualTo("Teatro di Prova")
        assertThat(claims.getStringClaim("entitlement")).isEqualTo("Biglietto accompagnatore")
        assertThat(claims.getStringClaim("outcome")).isEqualTo(GateReceipts.OUTCOME_VERIFIED)
        assertThat(claims.getStringClaim("operator")).isEqualTo("MP")
        assertThat(claims.getStringClaim("method")).isEqualTo(GateReceipts.METHOD_MANUAL_INPS_QR)
        // The whole point: nothing about the person is ever recorded.
        assertThat(claims.claims.keys)
            .doesNotContain("given_name", "family_name", "tax_code", "document_number", "notes")
        assertThat(receipts.verifySignature(receipt.jws)).isTrue()
    }

    @Test
    fun `a not-entitled outcome is recorded as such`(
        @TempDir dir: Path,
    ) {
        val receipts = GateReceipts(dir, "Teatro di Prova", clock)
        val receipt = receipts.issue("Tariffa ridotta titolare", entitled = false, operator = "MP")
        assertThat(receipt.outcome).isEqualTo(GateReceipts.OUTCOME_NOT_VERIFIED)
    }

    @Test
    fun `receipts survive a restart and are listed for today`(
        @TempDir dir: Path,
    ) {
        val first = GateReceipts(dir, "Teatro di Prova", clock)
        val issued = first.issue("Accesso prioritario", entitled = true, operator = "GB")
        // A brand new instance over the same data dir: same key, same records.
        val second = GateReceipts(dir, "Teatro di Prova", clock)
        assertThat(second.today().map { it.id }).containsExactly(issued.id)
        assertThat(second.byId(issued.id)?.jws).isEqualTo(issued.jws)
        assertThat(second.verifySignature(issued.jws)).isTrue()
    }

    @Test
    fun `a tampered receipt fails signature verification`(
        @TempDir dir: Path,
    ) {
        val receipts = GateReceipts(dir, "Teatro di Prova", clock)
        val receipt = receipts.issue("Biglietto accompagnatore", entitled = false, operator = "MP")
        val parts = receipt.jws.split('.')
        val tampered = parts[0] + "." + parts[1] + "." + parts[2].reversed()
        assertThat(receipts.verifySignature(tampered)).isFalse()
    }
}
