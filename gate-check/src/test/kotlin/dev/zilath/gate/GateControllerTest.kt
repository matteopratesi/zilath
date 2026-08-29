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
    fun `an unknown entitlement or a blank operator is refused`() {
        mockMvc
            .post("/gate/record") {
                header("Sec-Fetch-Site", "same-origin")
                param("entitlement", "Sconto inventato")
                param("operator", "MP")
                param("outcome", "verified")
            }.andExpect { status { isBadRequest() } }
        mockMvc
            .post("/gate/record") {
                header("Sec-Fetch-Site", "same-origin")
                param("entitlement", "Biglietto accompagnatore")
                param("operator", "  ")
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
