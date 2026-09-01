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

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.time.Clock

/**
 * A misconfiguration message is only useful if the reader can act on it, which means naming
 * the thing they actually set. The demo reads Spring properties, but every one of them is fed
 * from a `ZILATH_*` environment variable in `application.yml`; a message naming the property
 * leaves the reader to work out the mapping first.
 *
 * These tests pin both halves: that the message names environment variables, and that the
 * ones it names still exist. Renaming a variable in `application.yml` without touching the
 * message fails here rather than at somebody's first run.
 */
class ConfigurationMessagesTest {
    private val declaredEnvVars: Set<String> =
        ConfigurationMessagesTest::class.java
            .getResourceAsStream("/application.yml")!!
            .bufferedReader()
            .use { ENV_PLACEHOLDER.findAll(it.readText()).map { m -> m.groupValues[1] }.toSet() }

    @Test
    fun `missing trust anchor keys names the environment variables that supply them`() {
        val message = messageFrom(jwksPath = "", tofu = false)

        assertThat(message)
            .contains("ZILATH_TRUST_ANCHOR_JWKS_PATH")
            .contains("ZILATH_TRUST_ANCHOR_TOFU=true")
            .doesNotContain("zilath.demo.")
    }

    @Test
    fun `an unusable JWKS file names the variable that pointed at it`() {
        val empty = emptyJwks()

        val message = messageFrom(jwksPath = empty, tofu = false)

        assertThat(message)
            .contains("ZILATH_TRUST_ANCHOR_JWKS_PATH")
            .contains(empty)
            .doesNotContain("zilath.demo.")
    }

    @Test
    fun `a missing file names the variable that pointed at it`() {
        val absent = missingFile()

        val message = messageFrom(jwksPath = absent, tofu = false)

        assertThat(message).contains("ZILATH_TRUST_ANCHOR_JWKS_PATH").contains(absent)
    }

    @Test
    fun `the accepted key formats are described as parseJwks actually accepts them`() {
        val single =
            jwksFile(
                ECKeyGenerator(Curve.P_256)
                    .keyID("anchor")
                    .generate()
                    .toPublicJWK()
                    .toJSONString(),
            )

        // A single JWK object is accepted, so no message may claim a JWKS is required.
        assertThat(parseJwks(java.io.File(single).readText())).hasSize(1)
        assertThat(ACCEPTED_KEY_SHAPES).contains("single JWK object")

        val message = messageFrom(jwksPath = jwksFile("{\"not\": \"keys\"}"), tofu = false)
        assertThat(message).contains(ACCEPTED_KEY_SHAPES)
    }

    @Test
    fun `every environment variable named in a message is one the application reads`() {
        val named =
            listOf(
                messageFrom(jwksPath = "", tofu = false),
                messageFrom(jwksPath = emptyJwks(), tofu = false),
                messageFrom(jwksPath = jwksFile("{\"not\": \"keys\"}"), tofu = false),
                messageFrom(jwksPath = missingFile(), tofu = false),
            ).flatMap { ENV_VAR.findAll(it).map { m -> m.value } }.toSet()

        assertThat(named).isNotEmpty()
        assertThat(declaredEnvVars).containsAll(named)
    }

    /** A path inside a real directory that has no file at the end of it. */
    private fun missingFile(): String =
        kotlin.io.path
            .createTempDirectory()
            .resolve("not-there.json")
            .toString()

    private fun emptyJwks(): String = jwksFile("""{"keys":[]}""")

    private fun jwksFile(content: String): String =
        kotlin.io.path
            .createTempFile(suffix = ".json")
            .also { it.toFile().writeText(content) }
            .toString()

    private fun messageFrom(
        jwksPath: String,
        tofu: Boolean,
    ): String {
        var captured = ""
        assertThatThrownBy {
            ConformanceDemoApp().trustEvaluator(
                anchorId = "https://localhost:3001",
                jwksPath = jwksPath,
                tofu = tofu,
                insecureTls = false,
                clock = Clock.systemUTC(),
            )
        }.isInstanceOf(IllegalArgumentException::class.java)
            .satisfies({ captured = it.message.orEmpty() })
        return captured
    }

    private companion object {
        /** `${ZILATH_FOO:default}` in application.yml. */
        val ENV_PLACEHOLDER = Regex("""\$\{(ZILATH_[A-Z0-9_]+)[:}]""")

        /** A `ZILATH_FOO` token appearing in prose. */
        val ENV_VAR = Regex("""ZILATH_[A-Z0-9_]+""")
    }
}
