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
package dev.zilath.demo

import jakarta.servlet.http.Cookie
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@SpringBootTest(
    classes = [ConformanceDemoApp::class],
    properties = ["zilath.demo.trust-anchor-tofu=true"],
)
@AutoConfigureMockMvc
class DemoCheckoutSmokeTest {
    @Autowired
    lateinit var mockMvc: MockMvc

    /** A transaction started from the demo page, and the session cookie that owns it. */
    private class Started(
        val txId: String,
        val session: Cookie,
    )

    private fun startTransaction(): Started {
        val response =
            mockMvc
                .perform(get("/demo/entitled"))
                .andExpect(status().isFound)
                .andReturn()
                .response
        return Started(
            checkNotNull(response.getHeader("Location")).substringAfterLast('/'),
            checkNotNull(response.getCookie(DemoCheckoutController.SESSION_COOKIE)),
        )
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
        val started = startTransaction()
        val txId = started.txId
        mockMvc
            .perform(get("/demo/wait/{txId}", txId).cookie(started.session))
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.containsString("/demo/qr/$txId.png")))
            // The test wallet starts from the QR's authorize URL, as a wallet does.
            .andExpect(
                content().string(
                    org.hamcrest.Matchers.containsString("./scripts/run-demo-wallet.sh &#39;openid4vp://authorize?"),
                ),
            )
        mockMvc
            .perform(get("/demo/qr/{txId}.png", txId).cookie(started.session))
            .andExpect(status().isOk)
            .andExpect(content().contentType("image/png"))
        mockMvc
            .perform(get("/demo/authorize-url/{txId}", txId).cookie(started.session))
            .andExpect(status().isOk)
            .andExpect(content().string(org.hamcrest.Matchers.startsWith("openid4vp://authorize?")))
    }

    @Test
    fun `a transaction answers only the browser that started it`() {
        // The id is in the QR on the screen and in the same-device link: it opens nothing.
        val txId = startTransaction().txId
        val otherBrowser = startTransaction().session
        for (session in listOf(null, otherBrowser)) {
            fun request(path: String) = get(path, txId).apply { if (session != null) cookie(session) }
            mockMvc.perform(request("/demo/wait/{txId}")).andExpect(status().isNotFound)
            mockMvc.perform(request("/demo/qr/{txId}.png")).andExpect(status().isNotFound)
            mockMvc.perform(request("/demo/authorize-url/{txId}")).andExpect(status().isNotFound)
            mockMvc.perform(request("/demo/ticket/{txId}")).andExpect(status().isNotFound)
            mockMvc.perform(request("/demo/receipt/{txId}")).andExpect(status().isNotFound)
            mockMvc
                .perform(request("/demo/status/{txId}"))
                .andExpect(status().isOk)
                .andExpect(jsonPath("$.status").value("unknown"))
        }
    }

    @Test
    fun `a path that is no transaction id is not echoed back`() {
        mockMvc
            .perform(get("/demo/ticket/{txId}", "<img src=x onerror=alert(1)>"))
            .andExpect(status().isNotFound)
            .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("<img"))))
    }

    @Test
    fun `status is pending until the wallet answers, and the ticket is gated`() {
        val started = startTransaction()
        val status =
            mockMvc
                .perform(get("/demo/status/{txId}", started.txId).cookie(started.session))
                .andExpect(status().isOk)
                .andReturn()
                .response.contentAsString
        assertThat(status).contains("pending")
        mockMvc.perform(get("/demo/ticket/{txId}", started.txId).cookie(started.session)).andExpect(status().isConflict)
        mockMvc
            .perform(
                get("/demo/receipt/{txId}", started.txId).cookie(started.session),
            ).andExpect(status().isConflict)
    }

    @Test
    fun `unknown transactions get a not found page`() {
        mockMvc.perform(get("/demo/wait/{txId}", "ghost")).andExpect(status().isNotFound)
        mockMvc.perform(get("/demo/qr/{txId}.png", "ghost")).andExpect(status().isNotFound)
    }
}
