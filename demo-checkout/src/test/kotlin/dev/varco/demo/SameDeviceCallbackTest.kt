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
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

/**
 * The same-device return leg: an unknown session, a missing code and an error carried in
 * the query must be told apart — and none of them may look like a success.
 */
@SpringBootTest(
    classes = [ConformanceDemoApp::class],
    properties = ["varco.demo.trust-anchor-tofu=true"],
)
@AutoConfigureMockMvc
class SameDeviceCallbackTest {
    @Autowired
    lateinit var mockMvc: MockMvc

    private fun startSameDevice(): String {
        val location =
            mockMvc
                .perform(get("/demo/entitled").param("flow", "same-device"))
                .andExpect(status().isFound)
                .andReturn()
                .response
                .getHeader("Location")
        return checkNotNull(location).substringAfterLast('/')
    }

    @Test
    fun `an unknown session is unauthorized, not merely not-found`() {
        mockMvc
            .perform(get("/demo/cb/unknown-session").param("response_code", "whatever"))
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun `a known session without a response code is unauthorized`() {
        mockMvc
            .perform(get("/demo/cb/${startSameDevice()}"))
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun `an error carried in the query is a bad request, and never consumes anything`() {
        val txId = startSameDevice()
        mockMvc
            .perform(get("/demo/cb/$txId").param("error", "server_error").param("response_code", "x"))
            .andExpect(status().isBadRequest)
        // The code was not consumed by the error call: the invalid one still reports as such.
        mockMvc
            .perform(get("/demo/cb/$txId").param("response_code", "x"))
            .andExpect(status().isBadRequest)
    }

    @Test
    fun `an invalid response code on a known session is a bad request`() {
        val response =
            mockMvc
                .perform(get("/demo/cb/${startSameDevice()}").param("response_code", "not-a-real-code"))
                .andExpect(status().isBadRequest)
                .andReturn()
                .response.contentAsString
        assertThat(response).contains("invalid_response_code")
    }
}
