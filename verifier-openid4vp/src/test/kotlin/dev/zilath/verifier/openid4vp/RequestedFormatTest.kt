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

import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/** The request object announces the credential format its own query asks for. */
class RequestedFormatTest : FlowTestSupport() {
    private fun formatsAnnouncedFor(format: String): Map<*, *> {
        val query =
            Json
                .parseToJsonElement(
                    """{"credentials": [{"id": "pid", "format": "$format",
                        "meta": {"vct_values": ["urn:zilath:test:entitlement"]},
                        "claims": [{"path": ["given_name"]}]}]}""",
                ).jsonObject
        val started = flow.start(PresentationRequest(query, "pid"))
        val jar = SignedJWT.parse(checkNotNull(flow.requestJwtFor(started.id)))
        return jar.jwtClaimsSet.getJSONObjectClaim("client_metadata")["vp_formats_supported"] as Map<*, *>
    }

    @Test
    fun `a query for the pre-1_0 vc+sd-jwt announces that format, with the same algorithms`() {
        // The signed request asked for vc+sd-jwt while its metadata said the verifier
        // supported dc+sd-jwt alone: a wallet that checks one against the other refused it.
        val formats = formatsAnnouncedFor("vc+sd-jwt")
        assertThat(formats.keys).containsExactlyInAnyOrder("dc+sd-jwt", "vc+sd-jwt")
        assertThat(formats["vc+sd-jwt"]).isEqualTo(formats["dc+sd-jwt"])
    }

    @Test
    fun `a query for dc+sd-jwt announces that format alone`() {
        assertThat(formatsAnnouncedFor("dc+sd-jwt").keys).containsExactly("dc+sd-jwt")
    }
}
