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
package dev.zilath.verifier.core

import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Duration
import java.time.Instant
import java.util.Date
import java.util.concurrent.ConcurrentLinkedQueue
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.TrustManagerFactory

/**
 * The fetcher connects to the address the lookup gave, and to no other: over TLS that is
 * visible, because the names below exist in no resolver. A client that resolved the name again
 * to connect could not reach this server at all.
 */
class HttpDocumentFetcherTlsTest {
    private val requested = ConcurrentLinkedQueue<String>()
    private val resolved = ConcurrentLinkedQueue<String>()

    private val server =
        HttpsServer.create(InetSocketAddress(InetAddress.getByName(LOOPBACK), 0), 0).apply {
            httpsConfigurator = HttpsConfigurator(serverContext)
            createContext("/") { exchange ->
                requested += exchange.requestURI.path
                val body = "the document".toByteArray()
                exchange.sendResponseHeaders(200, body.size.toLong())
                exchange.responseBody.use { it.write(body) }
            }
            start()
        }

    private val port = server.address.port

    private fun fetcher(trust: SSLContext? = clientContext) =
        HttpDocumentFetcher(
            Duration.ofSeconds(2),
            Duration.ofSeconds(5),
            HttpDocumentFetcher.DEFAULT_MAX_RESPONSE_BYTES,
            destinations = HttpDocumentFetcher.Destinations.LOOPBACK,
            sslContext = trust,
            resolve = { host ->
                resolved += host
                listOf(InetAddress.getByName(LOOPBACK))
            },
        )

    @AfterEach
    fun stop() = server.stop(0)

    @Test
    fun `the connection goes to the address the lookup gave, which no other resolver knows`() {
        assertThat(fetcher().fetch("https://$CERTIFIED_NAME:$port/document")).isEqualTo("the document")
        assertThat(resolved).containsExactly(CERTIFIED_NAME)
        assertThat(requested).containsExactly("/document")
    }

    @Test
    fun `the certificate is verified against the name in the URL, not the address`() {
        assertThatThrownBy { fetcher().fetch("https://$OTHER_NAME:$port/document") }
            .isInstanceOf(SSLHandshakeException::class.java)
        assertThat(requested).isEmpty()
    }

    @Test
    fun `a certificate outside the TLS trust is refused`() {
        assertThatThrownBy { fetcher(trust = null).fetch("https://$CERTIFIED_NAME:$port/document") }
            .isInstanceOf(SSLHandshakeException::class.java)
        assertThat(requested).isEmpty()
    }

    private companion object {
        const val LOOPBACK = "127.0.0.1"
        const val CERTIFIED_NAME = "pinned.zilath.invalid"
        const val OTHER_NAME = "other.zilath.invalid"
        const val PASSWORD = "test"

        private val keyPair =
            KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

        /** Self-signed, valid for [CERTIFIED_NAME] from a day ago to a day from now. */
        private val certificate: X509Certificate =
            X500Name("CN=$CERTIFIED_NAME").let { name ->
                val holder =
                    JcaX509v3CertificateBuilder(
                        name,
                        BigInteger.ONE,
                        Date.from(Instant.now().minus(Duration.ofDays(1))),
                        Date.from(Instant.now().plus(Duration.ofDays(1))),
                        name,
                        keyPair.public,
                    ).addExtension(
                        Extension.subjectAlternativeName,
                        false,
                        GeneralNames(GeneralName(GeneralName.dNSName, CERTIFIED_NAME)),
                    ).build(JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.private))
                JcaX509CertificateConverter().getCertificate(holder)
            }

        val serverContext: SSLContext =
            SSLContext.getInstance("TLS").apply {
                val keys =
                    KeyStore.getInstance("PKCS12").apply {
                        load(null, null)
                        setKeyEntry("server", keyPair.private, PASSWORD.toCharArray(), arrayOf(certificate))
                    }
                val managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
                managers.init(keys, PASSWORD.toCharArray())
                init(managers.keyManagers, null, null)
            }

        val clientContext: SSLContext =
            SSLContext.getInstance("TLS").apply {
                val trusted =
                    KeyStore.getInstance("PKCS12").apply {
                        load(null, null)
                        setCertificateEntry("server", certificate)
                    }
                val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                managers.init(trusted)
                init(null, managers.trustManagers, null)
            }
    }
}
