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
package dev.zilath.verifier.spring

import dev.zilath.verifier.openid4vp.RelyingPartyConfiguration
import dev.zilath.verifier.openid4vp.RpEntityConfiguration
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.time.Clock

/**
 * Serves the relying party's entity configuration at `/.well-known/openid-federation`, with
 * the media type OpenID Federation 1.0 gives it, `application/entity-statement+jwt`.
 *
 * The path is the application's root: the entity configuration lives at the entity id
 * followed by `/.well-known/openid-federation`, so an entity id with a path of its own needs
 * the application served under that path. Signed anew for every request, since its `exp`
 * follows its `iat` by a day.
 */
@RestController
class OpenId4VpFederationController(
    private val config: RelyingPartyConfiguration,
    private val clock: Clock,
) {
    private val federation =
        checkNotNull(config.federation) { "the relying party configuration has no federation identity to publish" }

    @GetMapping(RpEntityConfiguration.WELL_KNOWN_PATH)
    fun entityConfiguration(): ResponseEntity<String> =
        ResponseEntity
            .ok()
            .contentType(ENTITY_STATEMENT_TYPE)
            .body(RpEntityConfiguration.build(config, federation, clock))

    private companion object {
        val ENTITY_STATEMENT_TYPE: MediaType = MediaType.parseMediaType(RpEntityConfiguration.MEDIA_TYPE)
    }
}
