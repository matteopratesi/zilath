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

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import dev.varco.verifier.core.CredentialStatus
import dev.varco.verifier.core.CredentialVerifier
import dev.varco.verifier.core.StatusChecker
import dev.varco.verifier.core.TrustEvaluator
import dev.varco.verifier.openid4vp.OpenId4VpVerificationFlow
import dev.varco.verifier.openid4vp.RelyingPartyConfiguration
import dev.varco.verifier.openid4vp.RpEndpoints
import dev.varco.verifier.openid4vp.RpKeys
import dev.varco.verifier.openid4vp.VerificationFlow
import dev.varco.verifier.trust.FederationTrustEvaluator
import dev.varco.verifier.trust.TrustAnchorConfig
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock

/**
 * Minimal runnable relying party for the PagoPA conformance runs (plan docs/03 §5-M0.4).
 * Ephemeral RP keys are generated at startup: nothing here is production material.
 *
 * Trust: when `varco.demo.trust-anchor-id` and `varco.demo.trust-anchor-jwks-path` are set,
 * credential issuers are validated through the OpenID Federation chain against that anchor
 * (the conformance tool spins a local one). Without them the app refuses to start: even a
 * demo never defaults to blind trust.
 */
@SpringBootApplication
class ConformanceDemoApp {
    @Bean
    fun statusChecker(): StatusChecker =
        StatusChecker {
            // Status list checks are exercised in unit tests; the conformance PID carries
            // no status reference, so a static VALID keeps the demo deterministic.
            CredentialStatus.VALID
        }

    @Bean
    fun trustEvaluator(
        @Value("\${varco.demo.trust-anchor-id}") anchorId: String,
        @Value("\${varco.demo.trust-anchor-jwks-path:}") jwksPath: String,
        @Value("\${varco.demo.trust-anchor-tofu:false}") tofu: Boolean,
        @Value("\${varco.demo.insecure-tls:false}") insecureTls: Boolean,
        clock: Clock,
    ): TrustEvaluator {
        val fetcher = httpFetcher(insecureTls)
        if (jwksPath.isNotBlank()) {
            val keys = parseJwks(Files.readString(Path.of(jwksPath)))
            require(keys.isNotEmpty()) { "no trust anchor keys found in $jwksPath" }
            return FederationTrustEvaluator(TrustAnchorConfig(anchorId, keys), fetcher, clock)
        }
        require(tofu) {
            "provide varco.demo.trust-anchor-jwks-path, or explicitly opt into " +
                "varco.demo.trust-anchor-tofu=true (conformance runs only)"
        }
        // TOFU: the anchor keys are taken from the anchor's own entity configuration at
        // first use. Acceptable ONLY against the conformance tool's ephemeral local anchor,
        // whose keys change at every run; never a production setup.
        return TofuFederationTrustEvaluator(anchorId, fetcher, clock)
    }

    @Bean
    fun demoClock(): Clock = Clock.systemUTC()

    @Bean
    @Suppress("LongParameterList") // Spring bean wiring: every parameter is an injected dependency
    fun verificationFlow(
        trustEvaluator: TrustEvaluator,
        statusChecker: StatusChecker,
        verifier: CredentialVerifier,
        clock: Clock,
        @Value("\${varco.demo.public-base-url:http://localhost:8080}") baseUrl: String,
        @Value("\${varco.demo.wallet-scheme:openid4vp://}") walletScheme: String,
        @Value("\${varco.demo.rp-pem-path:}") rpPemPath: String,
    ): VerificationFlow {
        val signingKey = loadOrGenerateSigningKey(rpPemPath)
        val config =
            RelyingPartyConfiguration(
                clientId = clientIdFor(signingKey, baseUrl),
                endpoints =
                    RpEndpoints(
                        requestUriBase = "$baseUrl/openid4vp/request",
                        responseUriBase = "$baseUrl/openid4vp/response",
                    ),
                keys =
                    RpKeys(
                        requestSigningKey = signingKey,
                        responseEncryptionKey = ECKeyGenerator(Curve.P_256).keyID("demo-rp-enc").generate(),
                    ),
                trustEvaluator = trustEvaluator,
                statusChecker = statusChecker,
                walletAuthorizationScheme = walletScheme,
            )
        return OpenId4VpVerificationFlow.withInMemoryStore(config, verifier, clock)
    }

    /**
     * With a PEM (self-signed certificate + EC P-256 private key) the demo speaks the
     * `x509_hash` client id scheme required by the conformance wallet; without it the
     * plain base URL is used and ephemeral keys are generated.
     */
    private fun loadOrGenerateSigningKey(rpPemPath: String): com.nimbusds.jose.jwk.ECKey {
        if (rpPemPath.isBlank()) {
            return ECKeyGenerator(Curve.P_256).keyID("demo-rp-sign").generate()
        }
        val pem = Files.readString(Path.of(rpPemPath))
        val parsed = JWK.parseFromPEMEncodedObjects(pem).toECKey()
        val certificateDer =
            pem
                .substringAfter("-----BEGIN CERTIFICATE-----")
                .substringBefore("-----END CERTIFICATE-----")
                .replace(Regex("\\s"), "")
        check(certificateDer.isNotBlank()) { "$rpPemPath contains no certificate" }
        return com.nimbusds.jose.jwk
            .ECKey
            .Builder(parsed)
            .keyID("demo-rp-sign")
            .x509CertChain(
                listOf(
                    com.nimbusds.jose.util
                        .Base64(certificateDer),
                ),
            ).build()
    }

    private fun clientIdFor(
        signingKey: com.nimbusds.jose.jwk.ECKey,
        baseUrl: String,
    ): String {
        val leafCertificate = signingKey.x509CertChain?.firstOrNull() ?: return baseUrl
        val digest =
            java.security.MessageDigest
                .getInstance("SHA-256")
                .digest(leafCertificate.decode())
        return "x509_hash:" +
            com.nimbusds.jose.util.Base64URL
                .encode(digest)
    }
}

/** Parses either a JWK Set document (`{"keys":[...]}`) or a single JWK document. */
internal fun parseJwks(document: String): List<JWK> =
    runCatching {
        com.nimbusds.jose.jwk.JWKSet
            .parse(document)
            .keys
    }.getOrElse { listOf(JWK.parse(document)) }

@Suppress("SpreadOperator") // canonical Spring Boot Kotlin entry point
fun main(args: Array<String>) {
    runApplication<ConformanceDemoApp>(*args)
}
