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
package dev.zilath.verifier.trust

import com.nimbusds.jose.jwk.JWK
import dev.zilath.verifier.core.IssuerTrustInput
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.TrustEvaluator
import java.time.Clock
import java.time.Duration

/**
 * [TrustEvaluator] for the IT-Wallet OpenID Federation profile (spec v1.4.x §6).
 *
 * Trust is anchored to [TrustAnchorConfig]: the anchor entity id and its federation
 * keys, obtained out-of-band.
 *
 * Evaluation order:
 * 1. Without a `trust_chain` JWS header the chain is resolved online: the leaf entity
 *    configuration from `{iss}/.well-known/openid-federation`, then subordinate statements
 *    walking `authority_hints` up to the configured anchor, via the injectable
 *    [FederationFetcher]. The anchor's own configuration is verified with the configured
 *    keys before its fetch endpoint is used.
 * 2. With a `trust_chain` header, the provided chain's shape and anchor are checked first —
 *    a malformed one is refused without any fetch — and then it is REFRESHED: resolved
 *    online as in 1, following the superiors it names. The header is signed by the issuer at
 *    issuance and never changes, so taking it as it is kept an issuer trusted until its
 *    statements expired, however long ago its superior withdrew it; IT-Wallet 1.4.6 §6.9 and
 *    §6.12.1 require the chain to be verifiable online and refreshed when a connection is
 *    available. A statement the superior no longer serves is a revocation.
 * 3. With [offlineFallback] the provided chain is refreshed along its own path, one
 *    statement at a time: the leaf's configuration and each superior's statement about the
 *    entity below it are fetched fresh, and only a document that cannot be fetched at all
 *    (the fetcher throws anything but [FederationDocumentNotFoundException]) is replaced by
 *    the copy the chain carries — an expired copy is then untrusted. Every answer that
 *    comes back is final, including "no such statement". The superiors are asked even when
 *    the leaf's own configuration cannot be fetched, which the leaf controls: a withdrawn
 *    statement is missed only while the superior that withdrew it cannot be reached.
 *
 * Every subordinate statement must be valid for at most [maxStatementLifetime], 24 hours by
 * default: IT-Wallet 1.4.6 §6.11.1 wants a revocation propagated within 24 hours, so a
 * trust chain must not be valid for longer than that, and a chain expires with its
 * earliest statement. Entity configurations are not capped: the production issuer's lives
 * 365 days.
 *
 * On success the decision carries the keys the issuer signs credentials with: the `jwks`
 * of its `openid_credential_issuer` metadata AFTER applying the `metadata_policy` of the
 * superior statements (merged anchor-first, OID-FED §6.1). There is no fallback: a leaf
 * whose resolved `openid_credential_issuer` metadata advertises no `jwks` is untrusted;
 * federation keys only ever verify entity statements. A policy conflict or violation
 * fails the evaluation. The decision also names the credential types the issuer may
 * issue ([TrustDecision.Trusted.credentialTypes]): the `vct` of every SD-JWT entry in the
 * same resolved metadata's `credential_configurations_supported` — none, and so no type at
 * all, when the section is absent. Trust marks are not checked.
 *
 * @param maxChainLength the most statements a trust chain may hold: the leaf's
 *   configuration and the subordinate statements up to the anchor's. The anchor's own
 *   configuration, which may close a provided chain, is not counted. Four by default: a
 *   leaf under two intermediates.
 * @param offlineFallback false (the default) for a relying party that is online — every
 *   decision reflects the federation as it is now. True for deployments that must keep
 *   working through an outage: a superior that cannot be reached is then answered for by
 *   its statement in the chain the credential carries, at the cost of not seeing that
 *   superior's revocations until it is reachable again.
 */
class FederationTrustEvaluator(
    anchor: TrustAnchorConfig,
    private val fetcher: FederationFetcher,
    clock: Clock,
    maxChainLength: Int = DEFAULT_MAX_CHAIN_LENGTH,
    private val offlineFallback: Boolean = false,
    maxStatementLifetime: Duration = DEFAULT_MAX_STATEMENT_LIFETIME,
) : TrustEvaluator {
    init {
        require(!maxStatementLifetime.isNegative && !maxStatementLifetime.isZero) {
            "the maximum statement lifetime must be positive"
        }
    }

    private val rules = ChainRules(anchor, clock, maxChainLength, maxStatementLifetime)

    override fun evaluate(issuerChain: IssuerTrustInput): TrustDecision =
        runCatching {
            // Before choosing a path: a credential without iss used to be refused online and
            // trusted offline, because the leaf of a provided chain was compared with the
            // issuer only when there was one. IT-Wallet 1.4.6 makes iss REQUIRED in the
            // credential, and the leaf must be the entity that issued it.
            val issuer = issuerChain.issuer ?: trustFail("credential has no iss claim")
            val provided = issuerChain.trustChain
            if (provided.isEmpty()) {
                validateChain(resolveChain(fetcher, issuer, rules), issuer, rules)
            } else {
                refreshedOrProvided(provided, issuer)
            }
        }.getOrElse { failure ->
            when (failure) {
                is TrustFailure -> TrustDecision.Untrusted(failure.message)
                // Never the exception's own message: a parser's may quote the input it choked
                // on, and the input here is a credential header or a federation document.
                else -> TrustDecision.Untrusted("trust evaluation failed")
            }
        }

    private fun refreshedOrProvided(
        provided: List<String>,
        issuer: String,
    ): TrustDecision.Trusted {
        val checked = providedChainOf(provided, issuer, rules)
        val refreshed =
            if (offlineFallback) {
                refreshAlongProvidedPath(fetcher, issuer, checked, rules)
            } else {
                resolveChain(fetcher, issuer, rules, checked.superiors)
            }
        return validateChain(refreshed, issuer, rules)
    }
}

/**
 * The trust anchor identity and federation keys, obtained out-of-band.
 *
 * Every key needs a `kid`, unique among them: the anchor's statements name the key that
 * signed them (OID-FED 1.0 §3), and only that key verifies them. The anchor's own entity
 * configuration publishes its keys with their `kid`s; copying that `jwks` is the way to
 * configure them.
 */
data class TrustAnchorConfig(
    val entityId: String,
    val federationKeys: List<JWK>,
) {
    init {
        require(federationKeys.isNotEmpty()) { "the trust anchor needs at least one federation key" }
        val kids = federationKeys.map { it.keyID }
        require(kids.none { it.isNullOrEmpty() } && kids.toSet().size == kids.size) {
            "every trust anchor federation key needs a kid, unique among them"
        }
    }
}

/**
 * Thrown by a [FederationFetcher] when the server ANSWERS that the document does not exist
 * — HTTP 404 or 410 from a well-known URL or a fetch endpoint. That is how a superior
 * withdraws an entity: it stops serving the statement about it. The evaluator takes it as
 * the federation's answer and fails the chain, even with an offline fallback, which covers
 * only a federation that cannot be reached. Any other exception from the fetcher counts as
 * not reached.
 */
class FederationDocumentNotFoundException(
    message: String? = null,
) : RuntimeException(message)

/**
 * Retrieves federation documents over HTTP; injectable so tests stay offline.
 *
 * SECURITY: every [url] derives from content an attacker may influence — the `iss` of a
 * credential nobody has verified yet, `authority_hints` and `federation_fetch_endpoint`
 * values from documents that are only verified once the chain closes at the anchor. The
 * library enforces their shape — https with a hostname, no userinfo, no IP literals —
 * with one exception: the exact loopback names (localhost, 127.0.0.1, [::1]) are also
 * accepted as plain http or as literals, so local development needs no TLS. It never
 * resolves names, so the network boundary is this implementation's job: set aggressive
 * timeouts, cap the response size, refuse redirects or re-check each redirect target
 * against the same rules — and when the deployment has an internal network to protect,
 * refuse destinations that resolve into it.
 */
fun interface FederationFetcher {
    /**
     * Returns the response body for [url]. Throws [FederationDocumentNotFoundException] when
     * the server says there is no such document, and any other exception on a transport
     * error.
     */
    fun fetch(url: String): String
}
