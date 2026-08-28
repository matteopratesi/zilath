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
package dev.zilath.demo.cedsim

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.SignedJWT
import java.net.URI
import java.net.URLDecoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.time.Clock

/**
 * Demo wallet presenting the SIMULATED CED (VARCO-38).
 *
 * Usage:
 *   init <keysDir>                 — generates the simulated federation keys
 *   run <txId> [baseUrl] [keysDir] — presents the simulated CED for a demo transaction
 */
object DemoWalletSimulator {
    private const val KEYS_DIR_ARG = 3
    private const val HTTP_OK_MIN = 200
    private const val HTTP_OK_MAX = 299
    private val http = HttpClient.newHttpClient()

    @JvmStatic
    fun main(args: Array<String>) {
        when (args.firstOrNull()) {
            "init" -> init(Path.of(args.getOrNull(1) ?: "demo-keys/ced-sim"))
            "run" ->
                run(
                    txId = requireNotNull(args.getOrNull(1)) { "usage: run <txId> [baseUrl] [keysDir]" },
                    baseUrl = args.getOrNull(2) ?: "http://localhost:8080",
                    keysDir = Path.of(args.getOrNull(KEYS_DIR_ARG) ?: "demo-keys/ced-sim"),
                )
            else -> error("usage: init <keysDir> | run <txId> [baseUrl] [keysDir]")
        }
    }

    private fun init(keysDir: Path) {
        CedSim.writeKeys(keysDir, CedSim.generateKeys())
        println("Simulated CED federation keys written to $keysDir")
        println("Start the app with:")
        println("  ZILATH_TRUST_ANCHOR_ID=${CedSim.ANCHOR_ID}")
        println("  ZILATH_TRUST_ANCHOR_JWKS_PATH=$keysDir/anchor-jwks.json")
        println("  ZILATH_DEMO_CREDENTIAL_MODE=ced-sim")
    }

    private fun run(
        txId: String,
        baseUrl: String,
        keysDir: Path,
    ) {
        val keys = CedSim.readKeys(keysDir)
        val authorizeUrl = get("$baseUrl/demo/authorize-url/$txId")
        val requestUri = queryParam(authorizeUrl, "request_uri")
        val jar = SignedJWT.parse(get(requestUri))
        val claims = jar.jwtClaimsSet
        val nonce = claims.getStringClaim("nonce")
        val state = claims.getStringClaim("state")
        val audience = claims.getStringClaim("client_id")
        val responseUri = claims.getStringClaim("response_uri")
        val encryptionKey = encryptionKeyOf(claims.getJSONObjectClaim("client_metadata"))
        val presentation = CedSim.mintPresentation(keys, nonce, audience, Clock.systemUTC())
        val response = CedSim.buildEncryptedResponse(state, presentation, encryptionKey)
        val status = postForm(responseUri, "response=" + java.net.URLEncoder.encode(response, StandardCharsets.UTF_8))
        check(status in HTTP_OK_MIN..HTTP_OK_MAX) { "wallet response rejected: HTTP $status" }
        println("Presented simulated CED for $txId -> HTTP $status")
    }

    private fun encryptionKeyOf(clientMetadata: Map<String, Any?>): JWK {
        val jwksMap = clientMetadata["jwks"] as Map<*, *>
        val keys = jwksMap["keys"] as List<*>

        @Suppress("UNCHECKED_CAST")
        return JWK.parse(JSONObjectUtils.toJSONString(keys.first() as Map<String, Any?>))
    }

    private fun queryParam(
        url: String,
        name: String,
    ): String {
        val query = URI.create(url).rawQuery ?: error("no query in $url")
        return query
            .split('&')
            .map { it.split('=', limit = 2) }
            .first { it[0] == name }
            .let { URLDecoder.decode(it[1], StandardCharsets.UTF_8) }
    }

    private fun get(url: String): String {
        val response =
            http.send(
                HttpRequest.newBuilder(URI.create(url)).GET().build(),
                HttpResponse.BodyHandlers.ofString(),
            )
        check(response.statusCode() in HTTP_OK_MIN..HTTP_OK_MAX) { "GET $url -> ${response.statusCode()}" }
        return response.body()
    }

    private fun postForm(
        url: String,
        body: String,
    ): Int {
        val request =
            HttpRequest
                .newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build()
        return http.send(request, HttpResponse.BodyHandlers.ofString()).statusCode()
    }
}
