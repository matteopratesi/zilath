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
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import dev.zilath.verifier.core.CredentialStatus
import dev.zilath.verifier.core.CredentialVerifier
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TrustEvaluator
import dev.zilath.verifier.openid4vp.OPENID_FEDERATION_PREFIX
import dev.zilath.verifier.openid4vp.OpenId4VpVerificationFlow
import dev.zilath.verifier.openid4vp.RelyingPartyConfiguration
import dev.zilath.verifier.openid4vp.RpEndpoints
import dev.zilath.verifier.openid4vp.RpEntityConfiguration
import dev.zilath.verifier.openid4vp.RpFederationConfig
import dev.zilath.verifier.openid4vp.RpKeys
import dev.zilath.verifier.openid4vp.VerificationFlow
import dev.zilath.verifier.openid4vp.VerificationReceipts
import dev.zilath.verifier.trust.FederationTrustEvaluator
import dev.zilath.verifier.trust.TrustAnchorConfig
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
 * Trust: when `zilath.demo.trust-anchor-id` and `zilath.demo.trust-anchor-jwks-path` are set,
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
        @Value("\${zilath.demo.trust-anchor-id}") anchorId: String,
        @Value("\${zilath.demo.trust-anchor-jwks-path:}") jwksPath: String,
        @Value("\${zilath.demo.trust-anchor-tofu:false}") tofu: Boolean,
        @Value("\${zilath.demo.insecure-tls:false}") insecureTls: Boolean,
        clock: Clock,
    ): TrustEvaluator {
        val fetcher = httpFetcher(insecureTls)
        if (jwksPath.isNotBlank()) {
            val keys = parseJwks(Files.readString(Path.of(jwksPath)))
            require(keys.isNotEmpty()) { "no trust anchor keys found in $jwksPath" }
            return FederationTrustEvaluator(TrustAnchorConfig(anchorId, keys), fetcher, clock)
        }
        require(tofu) {
            "provide zilath.demo.trust-anchor-jwks-path, or explicitly opt into " +
                "zilath.demo.trust-anchor-tofu=true (conformance runs only)"
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
    fun relyingPartyConfiguration(
        trustEvaluator: TrustEvaluator,
        statusChecker: StatusChecker,
        @Value("\${zilath.demo.public-base-url:http://localhost:8080}") baseUrl: String,
        @Value("\${zilath.demo.wallet-scheme:openid4vp://}") walletScheme: String,
        @Value("\${zilath.demo.rp-pem-path:}") rpPemPath: String,
        @Value("\${zilath.demo.trust-anchor-id}") anchorId: String,
        @Value("\${zilath.demo.client-id-scheme:x509-hash}") clientIdScheme: String,
        clock: Clock,
    ): RelyingPartyConfiguration {
        val signingKey = loadOrGenerateSigningKey(rpPemPath)
        val base =
            RelyingPartyConfiguration(
                clientId = clientIdFor(signingKey, baseUrl, clientIdScheme),
                endpoints =
                    RpEndpoints(
                        requestUriBase = "$baseUrl/openid4vp/request",
                        responseUriBase = "$baseUrl/openid4vp/response",
                        sameDeviceCallbackBase = "$baseUrl/demo/cb",
                    ),
                keys =
                    RpKeys(
                        requestSigningKey = signingKey,
                        responseEncryptionKey = ECKeyGenerator(Curve.P_256).keyID("demo-rp-enc").generate(),
                    ),
                trustEvaluator = trustEvaluator,
                statusChecker = statusChecker,
                walletAuthorizationScheme = walletScheme,
                // The demo publishes its entity configuration regardless of the client id
                // scheme in use: the federation onboarding side must be demonstrable
                // (VARCO-33) even while the conformance wallet mandates x509_hash.
                federation =
                    RpFederationConfig(
                        entityId = baseUrl,
                        federationKey = ECKeyGenerator(Curve.P_256).keyID("demo-rp-fed").generate(),
                        authorityHints = listOf(anchorId),
                        organizationName = "Zilath demo checkout",
                    ),
            )
        // The demo is its own federation: it travels with its self-signed entity
        // configuration as the chain, so a wallet can resolve the RP offline. A real
        // deployment carries the chain issued by its superior instead.
        val federation = checkNotNull(base.federation)
        return base.copy(
            federation = federation.copy(trustChain = listOf(RpEntityConfiguration.build(base, federation, clock))),
        )
    }

    @Bean
    fun verificationFlow(
        config: RelyingPartyConfiguration,
        verifier: CredentialVerifier,
        clock: Clock,
    ): VerificationFlow = OpenId4VpVerificationFlow.withInMemoryStore(config, verifier, clock)

    @Bean
    fun verificationReceipts(
        config: RelyingPartyConfiguration,
        clock: Clock,
    ): VerificationReceipts = VerificationReceipts(config, clock)

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

    /**
     * `openid-federation`: the RP is identified by its federation entity id, and wallets
     * resolve it through the entity configuration. `x509-hash` (default): identified by
     * the hash of its certificate, as the conformance wallet expects by default.
     */
    private fun clientIdFor(
        signingKey: com.nimbusds.jose.jwk.ECKey,
        baseUrl: String,
        scheme: String,
    ): String {
        val leafCertificate = signingKey.x509CertChain?.firstOrNull()
        return when {
            scheme == FEDERATION_SCHEME -> OPENID_FEDERATION_PREFIX + baseUrl
            leafCertificate == null -> baseUrl
            else ->
                "x509_hash:" +
                    com.nimbusds.jose.util.Base64URL
                        .encode(
                            java.security.MessageDigest
                                .getInstance("SHA-256")
                                .digest(leafCertificate.decode()),
                        ).toString()
        }
    }

    private companion object {
        const val FEDERATION_SCHEME = "openid-federation"
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
