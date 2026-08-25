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
package dev.varco.verifier.openid4vp

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import dev.varco.verifier.core.StatusChecker
import dev.varco.verifier.core.TrustEvaluator
import java.time.Duration

/** The public endpoints the wallet interacts with, without trailing slash. */
data class RpEndpoints(
    /** Base of the request object endpoint: the transaction id is appended as a path segment. */
    val requestUriBase: String,
    /** Base of the wallet response endpoint: the transaction id is appended as a path segment. */
    val responseUriBase: String,
)

data class RpKeys(
    /** EC P-256 key (with kid) signing the request objects. */
    val requestSigningKey: ECKey,
    /** EC P-256 key (with kid) the wallet encrypts responses to (`direct_post.jwt`). */
    val responseEncryptionKey: ECKey,
) {
    init {
        requireProfileKey("requestSigningKey", requestSigningKey)
        requireProfileKey("responseEncryptionKey", responseEncryptionKey)
    }

    private fun requireProfileKey(
        name: String,
        key: ECKey,
    ) {
        require(key.isPrivate) { "$name must contain private key material" }
        require(key.curve == Curve.P_256) { "$name must be a P-256 key (IT-Wallet profile)" }
        require(!key.keyID.isNullOrBlank()) { "$name must carry a kid (used in the JAR header)" }
    }

    /** Nimbus keys serialize their private parameters: never let them reach a log. */
    override fun toString(): String =
        "RpKeys(requestSigningKey=kid:${requestSigningKey.keyID}, " +
            "responseEncryptionKey=kid:${responseEncryptionKey.keyID})"
}

data class RelyingPartyConfiguration(
    /** The RP identifier: also the audience the key binding JWT must be addressed to. */
    val clientId: String,
    val endpoints: RpEndpoints,
    val keys: RpKeys,
    val trustEvaluator: TrustEvaluator,
    val statusChecker: StatusChecker,
    /** URI scheme of the QR payload; IT-Wallet accepts `openid4vp://` and `haip-vp://`. */
    val walletAuthorizationScheme: String = DEFAULT_SCHEME,
    val transactionTimeToLive: Duration = DEFAULT_TIME_TO_LIVE,
    /** The wallet profile in force; the Italian IT-Wallet profile is the default. */
    val profile: WalletProfile = ItWalletProfile,
) {
    companion object {
        const val DEFAULT_SCHEME = "openid4vp://"
        val DEFAULT_TIME_TO_LIVE: Duration = Duration.ofMinutes(5)
    }
}
