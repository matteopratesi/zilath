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
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.SignedJWT
import dev.zilath.verifier.core.InternalZilathApi
import dev.zilath.verifier.core.mediaTypeMatches
import java.time.Clock
import java.time.Duration
import java.time.Instant

internal const val ENTITY_STATEMENT_TYP = "entity-statement+jwt"
internal const val WELL_KNOWN_FEDERATION = "/.well-known/openid-federation"

/**
 * Why a chain is not trusted. Its message becomes [dev.zilath.verifier.core.TrustDecision.Untrusted.reason]
 * and, through the verifier, the `detail` of a rejection — which travels with the result
 * and ends up in logs. So it is a fixed phrase, interpolating at most a value of this
 * library or of the integrator's configuration (a chain position, a configured limit, the
 * configured anchor): never an identifier, claim or name read from a credential or a
 * federation document. The fourth internal review found `iss`, `sub` and policy names
 * echoed there before any signature check, unbounded and with CR/LF — forged log lines and
 * hundreds of kilobytes per request from anyone holding a transaction id.
 */
internal open class TrustFailure(
    message: String,
) : RuntimeException(message)

/**
 * The federation could not be asked: the [FederationFetcher] failed to bring back an
 * answer. Distinct from every other failure because it is the only one an evaluator in
 * offline-fallback mode may answer with the chain the credential carried — an answer
 * that says no, including "no such statement", is never papered over.
 */
internal class FederationUnreachable(
    message: String,
) : TrustFailure(message)

internal fun trustFail(message: String): Nothing = throw TrustFailure(message)

/** A parsed (not yet signature-verified) federation entity statement. */
internal class EntityStatement(
    val serialized: String,
    val jwt: SignedJWT,
) {
    private val claims = jwt.jwtClaimsSet

    val issuer: String = claims.issuer ?: trustFail("entity statement without iss")
    val subject: String = claims.subject ?: trustFail("entity statement without sub")
    val expiresAt: Instant = claims.expirationTime?.toInstant() ?: trustFail("entity statement without exp")
    val issuedAt: Instant = claims.issueTime?.toInstant() ?: trustFail("entity statement without iat")

    val authorityHints: List<String>
        get() = runCatching { claims.getStringListClaim("authority_hints") }.getOrNull().orEmpty()

    /**
     * The federation keys of the entity this statement is about (`jwks.keys`).
     *
     * OID-FED 1.0 §3.1.1: "Every JWK in the JWK Set MUST have a unique kid". A key without
     * one, or two with the same, fail the chain: the next statement down is verified with
     * the key its `kid` names, and a set in which a `kid` names nothing, or two keys, cannot
     * answer that.
     */
    val federationJwks: List<JWK>
        get() {
            val container = runCatching { claims.getJSONObjectClaim("jwks") }.getOrNull()
            val kids = (container?.get("keys") as? List<*>).orEmpty().map { (it as? Map<*, *>)?.get("kid") as? String }
            if (kids.any { it.isNullOrEmpty() } || kids.toSet().size != kids.size) {
                trustFail("an entity statement's jwks has a key without a unique kid")
            }
            return jwksOf(container)
        }

    /** The keys the entity signs credentials with (`metadata.openid_credential_issuer.jwks`). */
    val credentialIssuerJwks: List<JWK>
        get() = jwksOf(metadataSection("openid_credential_issuer")?.get("jwks") as? Map<*, *>)

    /** The full `metadata` claim, if any. Absent is fine; malformed fails the chain. */
    val metadata: Map<*, *>?
        get() = objectClaimOrFail("metadata")

    /** The `metadata_policy` of a subordinate statement, if any. A malformed one must
     *  fail the chain, never be silently ignored: it is a SIGNED superior directive. */
    val metadataPolicy: Map<*, *>?
        get() = objectClaimOrFail("metadata_policy")

    /** The `constraints` of a subordinate statement (OID-FED §6.2), if any; malformed fails. */
    val constraints: Map<*, *>?
        get() = objectClaimOrFail("constraints")

    /**
     * The operator names in `metadata_policy_crit` (OID-FED §3.1.3), empty when absent. When
     * present it must be a non-empty array of strings: an empty or malformed list of what
     * MUST be understood is not something to guess at.
     */
    val metadataPolicyCrit: Set<String>
        get() {
            if (!claims.claims.containsKey("metadata_policy_crit")) return emptySet()
            val names = claims.claims["metadata_policy_crit"] as? List<*>
            if (names.isNullOrEmpty() || names.any { it !is String }) {
                trustFail("an entity statement carries a malformed metadata_policy_crit")
            }
            return names.filterIsInstance<String>().toSet()
        }

    private fun objectClaimOrFail(name: String): Map<*, *>? {
        // Nimbus returns null both for an absent claim and for an explicit `null`:
        // membership must be checked on the claims map, and a PRESENT claim must be a
        // non-null JSON object — anything else fails the chain.
        if (!claims.claims.containsKey(name)) return null
        return runCatching { claims.getJSONObjectClaim(name) }.getOrNull()
            ?: trustFail("entity statement claim $name is malformed")
    }

    /** Whether the payload names [claim] at all, whatever its value. */
    fun hasClaim(claim: String): Boolean = claims.claims.containsKey(claim)

    val federationFetchEndpoint: String?
        get() = metadataSection("federation_entity")?.get("federation_fetch_endpoint") as? String

    private fun metadataSection(name: String): Map<*, *>? {
        val metadata = runCatching { claims.getJSONObjectClaim("metadata") }.getOrNull() ?: return null
        return metadata[name] as? Map<*, *>
    }
}

@OptIn(InternalZilathApi::class)
private fun typIsEntityStatement(jwt: SignedJWT): Boolean =
    mediaTypeMatches(jwt.header.type?.toString(), ENTITY_STATEMENT_TYP)

internal fun parseStatement(serialized: String): EntityStatement {
    val jwt =
        runCatching { SignedJWT.parse(serialized) }
            .getOrElse { trustFail("entity statement does not parse as a JWT") }
    if (!typIsEntityStatement(jwt)) {
        trustFail("entity statement typ is not $ENTITY_STATEMENT_TYP")
    }
    val claims =
        runCatching { jwt.jwtClaimsSet }.getOrElse {
            trustFail(
                "entity statement payload is not a JSON object",
            )
        }
    // OID-FED §3.2: every claim listed in `crit` "MUST be understood and be able to be
    // processed", and this library understands no extension claim — so a statement that
    // lists any, well-formed or not, is one it must not act on. Nimbus enforces only the
    // JOSE header's crit, never this payload claim, and it used to be ignored: a superior
    // making an extension mandatory (a revocation flag, say) was silently overruled.
    if (claims.claims.containsKey("crit")) {
        trustFail("an entity statement lists critical claims this library does not understand")
    }
    return EntityStatement(serialized, jwt)
}

internal fun jwksOf(container: Map<*, *>?): List<JWK> {
    val keys = container?.get("keys") as? List<*> ?: return emptyList()
    return keys.mapNotNull { key ->
        (key as? Map<*, *>)?.let { entry ->
            @Suppress("UNCHECKED_CAST")
            runCatching { JWK.parse(JSONObjectUtils.toJSONString(entry as Map<String, Any?>)) }.getOrNull()
        }
    }
}

internal const val DEFAULT_MAX_CHAIN_LENGTH = 4

/** IT-Wallet 1.4.6 §6.11.1: a subordinate statement is valid for at most 24 hours. */
internal val DEFAULT_MAX_STATEMENT_LIFETIME: Duration = Duration.ofHours(MAX_STATEMENT_LIFETIME_HOURS)

private const val MAX_STATEMENT_LIFETIME_HOURS = 24L

/** What a chain is validated against: the evaluator's configuration, in one place. */
internal class ChainRules(
    val anchor: TrustAnchorConfig,
    val clock: Clock,
    val maxChainLength: Int = DEFAULT_MAX_CHAIN_LENGTH,
    val maxStatementLifetime: Duration = DEFAULT_MAX_STATEMENT_LIFETIME,
)

/** Tolerance for a federation peer's clock differing from ours. */
internal val CLOCK_SKEW: Duration = Duration.ofMinutes(1)
