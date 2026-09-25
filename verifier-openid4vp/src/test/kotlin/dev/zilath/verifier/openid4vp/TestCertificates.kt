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

import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.MessageDigest
import java.time.Instant
import java.util.Date

/** [key] carrying an `x5c` chain of one: a self-signed certificate for its public half. */
internal fun withSelfSignedCertificate(key: ECKey): ECKey {
    val name = X500Name("CN=rp.example")
    val certificate =
        JcaX509v3CertificateBuilder(
            name,
            BigInteger.ONE,
            Date.from(Instant.parse("2026-01-01T00:00:00Z")),
            Date.from(Instant.parse("2036-01-01T00:00:00Z")),
            name,
            key.toECPublicKey(),
        ).build(JcaContentSignerBuilder("SHA256withECDSA").build(key.toECPrivateKey()))
    return ECKey.Builder(key).x509CertChain(listOf(Base64.encode(certificate.encoded))).build()
}

/**
 * The `x509_hash` client id of [key]'s leaf certificate, computed as OpenID4VP 1.0 §5.9.3
 * writes it — base64url of the SHA-256 of the DER — with the JDK's encoder, not the
 * library's code.
 */
internal fun x509HashClientIdOf(key: ECKey): String {
    val der = key.x509CertChain.first().decode()
    val hash = MessageDigest.getInstance("SHA-256").digest(der)
    return "x509_hash:" +
        java.util.Base64
            .getUrlEncoder()
            .withoutPadding()
            .encodeToString(hash)
}
