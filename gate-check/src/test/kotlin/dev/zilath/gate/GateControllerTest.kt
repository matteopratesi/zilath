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

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.post
import java.nio.file.Files

@SpringBootTest
@AutoConfigureMockMvc
class GateControllerTest(
    @Autowired private val mockMvc: MockMvc,
) {
    @Test
    fun `the full gate flow records only the outcome and shows the signed receipt`() {
        val redirect =
            mockMvc
                .post("/gate/record") {
                    header("Sec-Fetch-Site", "same-origin")
                    param("entitlement", "Biglietto accompagnatore")
                    param("operator", "MP")
                    param("reference", "ORD-2026-0417")
                    param("outcome", "verified")
                }.andExpect { status { isFound() } }
                .andReturn()
                .response
                .getHeader("Location")
        val receiptPage =
            mockMvc
                .get(redirect!!)
                .andExpect { status { isOk() } }
                .andReturn()
                .response.contentAsString
        assertThat(receiptPage).contains("Diritto verificato")
        assertThat(receiptPage).doesNotContain("MARIO", "ROSSI") // no person, ever
        mockMvc
            .get("/gate/today")
            .andExpect { status { isOk() } }
            .andReturn()
            .response.contentAsString
            .let { assertThat(it).contains("Biglietto accompagnatore") }
    }

    @Test
    fun `a receipt without a ticket reference is refused`() {
        // Without it a receipt proves that a check happened but not what it authorised,
        // which is the one thing a venue needs when reconciling takings later. The field
        // is a commercial identifier — an order number, a seat — never a person.
        mockMvc
            .post("/gate/record") {
                header("Sec-Fetch-Site", "same-origin")
                param("entitlement", "Biglietto accompagnatore")
                param("operator", "MP")
                param("reference", "   ")
                param("outcome", "verified")
            }.andExpect { status { isBadRequest() } }
    }

    @Test
    fun `a reference that is plainly personal data is refused`() {
        // The field cannot tell a booking code from a surname, so this is not a guarantee —
        // but an email address and a tax code are unambiguous, and catching them keeps an
        // obvious paste from ending up in a signed receipt.
        listOf("mario.rossi@example.com", "RSSMRA80A01H501U").forEach { personal ->
            mockMvc
                .post("/gate/record") {
                    header("Sec-Fetch-Site", "same-origin")
                    param("entitlement", "Biglietto accompagnatore")
                    param("operator", "MP")
                    param("reference", personal)
                    param("outcome", "verified")
                }.andExpect { status { isBadRequest() } }
        }
    }

    @Test
    fun `a reference is validated after trimming, not before`() {
        // Regression: the length check ran on the raw value while the stored one was
        // trimmed, so a full-length reference with pasted whitespace was rejected for a
        // length it never actually had.
        val padded = "  " + "A".repeat(60) + "  "
        mockMvc
            .post("/gate/record") {
                header("Sec-Fetch-Site", "same-origin")
                param("entitlement", "Biglietto accompagnatore")
                param("operator", "MP")
                param("reference", padded)
                param("outcome", "verified")
            }.andExpect { status { isFound() } }
    }

    @Test
    fun `the reference reaches the signed receipt and the day's list`() {
        val redirect =
            mockMvc
                .post("/gate/record") {
                    header("Sec-Fetch-Site", "same-origin")
                    param("entitlement", "Biglietto accompagnatore")
                    param("operator", "MP")
                    param("reference", "ORD-2026-0417 posto H12")
                    param("outcome", "verified")
                }.andReturn()
                .response
                .getHeader("Location")!!
        val receiptPage =
            mockMvc
                .get(redirect)
                .andReturn()
                .response.contentAsString
        assertThat(receiptPage).contains("ORD-2026-0417 posto H12")

        val today =
            mockMvc
                .get("/gate/today")
                .andReturn()
                .response.contentAsString
        assertThat(today).contains("ORD-2026-0417 posto H12")
    }

    @Test
    fun `both outcome buttons are legible, not just present`() {
        // Regression: the red button carried `class="btn no"`, and the bare `.no` rule —
        // shared with the outcome text — set the same colour as its background at equal
        // specificity. The label was in the markup and invisible on screen, at a contrast
        // ratio of 1:1, on a tool whose whole subject is accessibility.
        val page =
            mockMvc
                .get("/gate/new")
                .andReturn()
                .response.contentAsString
        assertThat(page).contains("Diritto verificato", "Diritto non verificato")
        assertThat(page).contains(".btn.no { background: #7f1d1d; color: #fff; }")
    }

    @Test
    fun `an unknown entitlement or a blank operator is refused`() {
        mockMvc
            .post("/gate/record") {
                header("Sec-Fetch-Site", "same-origin")
                param("entitlement", "Sconto inventato")
                param("operator", "MP")
                param("reference", "ORD-2026-0417")
                param("outcome", "verified")
            }.andExpect { status { isBadRequest() } }
        mockMvc
            .post("/gate/record") {
                header("Sec-Fetch-Site", "same-origin")
                param("entitlement", "Biglietto accompagnatore")
                param("operator", "  ")
                param("reference", "ORD-2026-0417")
                param("outcome", "verified")
            }.andExpect { status { isBadRequest() } }
    }

    @Test
    fun `a cross-site form post cannot mint a receipt`() {
        // Binding to 127.0.0.1 keeps the network out. It does nothing about a browser on
        // the door machine following a page that submits a form here — and a receipt is
        // signed with the venue's key, so a forged one is indistinguishable from a real
        // check. A cross-site form POST cannot forge Sec-Fetch-Site.
        for (site in listOf("cross-site", "same-site", null)) {
            mockMvc
                .post("/gate/record") {
                    if (site != null) header("Sec-Fetch-Site", site)
                    param("entitlement", "Biglietto accompagnatore")
                    param("operator", "MP")
                    param("reference", "ORD-2026-0417")
                    param("outcome", "verified")
                }.andExpect { status { isForbidden() } }
        }
    }

    @Test
    fun `an unknown receipt id is a 404 page`() {
        mockMvc.get("/gate/receipt/nope").andExpect { status { isNotFound() } }
    }

    companion object {
        @JvmStatic
        @DynamicPropertySource
        fun props(registry: DynamicPropertyRegistry) {
            registry.add("zilath.gate.data-dir") { Files.createTempDirectory("gate-test").toString() }
        }
    }
}
