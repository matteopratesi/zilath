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
package dev.varco.demo

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@SpringBootTest(
    classes = [ConformanceDemoApp::class],
    properties = ["varco.demo.trust-anchor-tofu=true"],
)
@AutoConfigureMockMvc
class DemoCheckoutSmokeTest {
    @Autowired
    lateinit var mockMvc: MockMvc

    private fun startTransaction(): String {
        val location =
            mockMvc
                .perform(get("/demo/entitled"))
                .andExpect(status().isFound)
                .andReturn()
                .response
                .getHeader("Location")
        return checkNotNull(location).substringAfterLast('/')
    }

    @Test
    fun `the entity configuration is served at the well-known path`() {
        val body =
            mockMvc
                .perform(get("/.well-known/openid-federation"))
                .andExpect(status().isOk)
                .andExpect(content().contentTypeCompatibleWith("application/entity-statement+jwt"))
                .andReturn()
                .response.contentAsString
        val claims =
            com.nimbusds.jwt.SignedJWT
                .parse(body)
                .jwtClaimsSet
        assertThat(claims.subject).isEqualTo("http://localhost:8080")
        assertThat(claims.getJSONObjectClaim("metadata")).containsKey("openid_credential_verifier")
    }

    @Test
    fun `the event page offers the companion ticket`() {
        mockMvc
            .perform(get("/demo"))
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString("biglietto accompagnatore")))
    }

    @Test
    fun `starting a purchase yields a waiting page with a QR`() {
        val txId = startTransaction()
        mockMvc
            .perform(get("/demo/wait/{txId}", txId))
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString("/demo/qr/$txId.png")))
        mockMvc
            .perform(get("/demo/qr/{txId}.png", txId))
            .andExpect(status().isOk)
            .andExpect(content().contentType("image/png"))
        mockMvc
            .perform(get("/demo/authorize-url/{txId}", txId))
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.startsWith("openid4vp://authorize?")))
    }

    @Test
    fun `status is pending until the wallet answers, and the ticket is gated`() {
        val txId = startTransaction()
        val status =
            mockMvc
                .perform(get("/demo/status/{txId}", txId))
                .andExpect(status().isOk)
                .andReturn()
                .response.contentAsString
        assertThat(status).contains("pending")
        mockMvc.perform(get("/demo/ticket/{txId}", txId)).andExpect(status().isConflict)
        mockMvc.perform(get("/demo/receipt/{txId}", txId)).andExpect(status().isConflict)
    }

    @Test
    fun `unknown transactions get a not found page`() {
        mockMvc.perform(get("/demo/wait/{txId}", "ghost")).andExpect(status().isNotFound)
        mockMvc.perform(get("/demo/qr/{txId}.png", "ghost")).andExpect(status().isNotFound)
    }
}
