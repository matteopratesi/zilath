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

import com.nimbusds.jose.jwk.RSAKey
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Clock
import java.time.Duration
import java.time.ZoneOffset

/*
 * What the pipeline tests share: a context at [TestVectors.NOW] that accepts
 * [TestVectors.vector] as it comes, and one way to run the verifier.
 */

@Suppress("LongParameterList") // one defaulted axis per field of the context
internal fun testContext(
    nonce: String = TestVectors.NONCE,
    audiences: Set<String> = setOf(TestVectors.AUDIENCE),
    trust: TrustEvaluator = TestVectors.trustIssuerEc(),
    status: StatusChecker = StatusChecker { _, _ -> CredentialStatus.VALID },
    expectedVcts: Set<String> = emptySet(),
    requestedClaims: RequestedClaims? = null,
    keyBindingMaxAge: Duration = VerificationContext.DEFAULT_KEY_BINDING_MAX_AGE,
) = VerificationContext(
    expectedNonce = nonce,
    expectedAudiences = audiences,
    clock = Clock.fixed(TestVectors.NOW, ZoneOffset.UTC),
    trustEvaluator = trust,
    statusChecker = status,
    keyBindingMaxAge = keyBindingMaxAge,
    expectedVcts = expectedVcts,
    requestedClaims = requestedClaims,
)

internal fun verifyPresentation(
    compact: String,
    ctx: VerificationContext = testContext(),
): VerificationResult = SdJwtVcCredentialVerifier().verify(RawPresentation.SdJwtVcPresentation(compact), ctx)

/** Nimbus refuses to GENERATE a key this small, which is the whole point: it will verify with one. */
internal fun weakRsaKey(bits: Int): RSAKey {
    val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair()
    return RSAKey
        .Builder(pair.public as RSAPublicKey)
        .privateKey(pair.private as RSAPrivateKey)
        .keyID("rsa-$bits")
        .build()
}
