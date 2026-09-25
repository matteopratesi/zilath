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

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.TrustEvaluator
import java.time.Duration

/** The public endpoints the wallet interacts with, without trailing slash. */
data class RpEndpoints(
    /** Base of the request object endpoint: the transaction id is appended as a path segment. */
    val requestUriBase: String,
    /** Base of the wallet response endpoint: the transaction id is appended as a path segment. */
    val responseUriBase: String,
    /**
     * Where the same-device flow brings the user back (`?response_code=...` is
     * appended). Null when the RP offers the cross-device flow only.
     */
    val sameDeviceCallbackBase: String? = null,
)

/**
 * The two key pairs the relying party needs. Both carry PRIVATE material, so an instance
 * must never be logged or serialized — [toString] is overridden to print only the kids,
 * and that override is a safety measure, not a formatting choice.
 */
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

/**
 * Everything one relying party is: who it says it is, where wallets reach it, what it
 * signs and decrypts with, and whom it trusts.
 *
 * Safe to share across transactions — the per-transaction state lives in the
 * [TransactionStore]. Its `init` block enforces the coherence rules that would otherwise
 * surface as unexplained wallet failures at runtime, so an invalid configuration fails at
 * construction rather than at the first presentation.
 *
 * One caveat on immutability: the list properties of [RpFederationConfig]
 * (`authorityHints`, `contacts`, `trustChain`) are held by reference, NOT defensively
 * copied. Mutating a list you passed in changes what later JARs and entity configurations
 * are built from, and the `init` validation will not run again. Pass lists you do not keep
 * a handle on.
 */
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
    /**
     * Federation-side identity: required for the `openid_federation:` client
     * id scheme — entity configuration endpoint, onboarding, JAR `trust_chain` header.
     * Absent for the `x509_hash` scheme.
     */
    val federation: RpFederationConfig? = null,
    /**
     * The largest wallet response body, in characters, the flow will decode. Above it the
     * response is rejected as malformed before any decoding or decryption. The default,
     * [DEFAULT_MAX_WALLET_RESPONSE_LENGTH], is four times a realistic worst case; a servlet
     * container may cut the body earlier (Tomcat's form limit is 2 MiB, Jetty's 200 000
     * bytes), and that limit must stay above this one or holders are refused there.
     */
    val maxWalletResponseLength: Int = DEFAULT_MAX_WALLET_RESPONSE_LENGTH,
) {
    init {
        require(maxWalletResponseLength > 0) { "maxWalletResponseLength must be positive" }
        require(transactionTimeToLive > Duration.ZERO) {
            "transactionTimeToLive must be positive: zero or less expires every transaction as it is created"
        }
        // The fourth internal review found no upper bound: Duration.ofSeconds(Long.MAX_VALUE)
        // passed here and overflowed in createdAt + ttl at the first request object, as a
        // runtime failure instead of a startup one. A merely large value is no better: the
        // request object's exp, the window in which a leaked QR or transaction id stays
        // usable and the time the disclosed claims are kept all follow this one number.
        require(transactionTimeToLive <= MAX_TIME_TO_LIVE) {
            "transactionTimeToLive must not exceed $MAX_TIME_TO_LIVE: the request object expiry, the " +
                "window in which a transaction id is usable and the retention of the disclosed claims all follow it"
        }
        // Under the openid_federation scheme the wallet resolves us through the trust
        // chain and checks client_id against our entity configuration `sub` (WP_086):
        // a config without federation identity, or with a mismatched one, can never work.
        if (clientId.startsWith(OPENID_FEDERATION_PREFIX)) {
            requireNotNull(federation) {
                "the openid_federation client id scheme requires a federation configuration"
            }
            require(clientId.removePrefix(OPENID_FEDERATION_PREFIX) == federation.entityId) {
                "client_id and federation entityId must agree under the openid_federation scheme"
            }
        }
    }

    companion object {
        const val DEFAULT_SCHEME = "openid4vp://"
        val DEFAULT_TIME_TO_LIVE: Duration = Duration.ofMinutes(5)

        /**
         * The longest accepted [transactionTimeToLive]. A presentation takes the holder
         * minutes, not hours; an hour leaves room for a slow checkout without letting a
         * transaction outlive the visit it belongs to.
         */
        val MAX_TIME_TO_LIVE: Duration = Duration.ofHours(1)

        /**
         * 1 MiB. Not the "few KiB" an SD-JWT VC with a key binding usually weighs: an
         * issuer may put its trust chain in the credential header — the real IT-Wallet
         * disability card issuer's entity configuration alone is 39 668 bytes, 48 KB with
         * the anchor's statement — and a disclosed portrait adds tens of KB more, each
         * base64url-encoded again inside the response JWE: a few hundred KB can be genuine,
         * and refusing a genuine holder's response for its size would be the worse failure.
         */
        const val DEFAULT_MAX_WALLET_RESPONSE_LENGTH: Int = 1024 * 1024
    }
}
