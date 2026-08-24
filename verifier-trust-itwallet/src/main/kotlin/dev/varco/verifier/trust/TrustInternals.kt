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
package dev.varco.verifier.trust

import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.SignedJWT
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.Clock
import java.time.Instant

internal const val ENTITY_STATEMENT_TYP = "entity-statement+jwt"
internal const val WELL_KNOWN_FEDERATION = "/.well-known/openid-federation"

internal class TrustFailure(
    message: String,
) : RuntimeException(message)

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

    /** The federation keys of the entity this statement is about (`jwks.keys`). */
    val federationJwks: List<JWK>
        get() = jwksOf(runCatching { claims.getJSONObjectClaim("jwks") }.getOrNull())

    /** The keys the entity signs credentials with (`metadata.openid_credential_issuer.jwks`). */
    val credentialIssuerJwks: List<JWK>
        get() = jwksOf(metadataSection("openid_credential_issuer")?.get("jwks") as? Map<*, *>)

    val federationFetchEndpoint: String?
        get() = metadataSection("federation_entity")?.get("federation_fetch_endpoint") as? String

    private fun metadataSection(name: String): Map<*, *>? {
        val metadata = runCatching { claims.getJSONObjectClaim("metadata") }.getOrNull() ?: return null
        return metadata[name] as? Map<*, *>
    }
}

internal fun parseStatement(serialized: String): EntityStatement {
    val jwt =
        runCatching { SignedJWT.parse(serialized) }
            .getOrElse { trustFail("entity statement does not parse as a JWT") }
    if (jwt.header.type?.toString() != ENTITY_STATEMENT_TYP) {
        trustFail("entity statement typ is not $ENTITY_STATEMENT_TYP")
    }
    return EntityStatement(serialized, jwt)
}

private fun jwksOf(container: Map<*, *>?): List<JWK> {
    val keys = container?.get("keys") as? List<*> ?: return emptyList()
    return keys.mapNotNull { key ->
        (key as? Map<*, *>)?.let { entry ->
            @Suppress("UNCHECKED_CAST")
            runCatching { JWK.parse(JSONObjectUtils.toJSONString(entry as Map<String, Any?>)) }.getOrNull()
        }
    }
}

internal fun fetchEntityConfiguration(
    fetcher: FederationFetcher,
    entityId: String,
): EntityStatement {
    val body =
        runCatching { fetcher.fetch(entityId.trimEnd('/') + WELL_KNOWN_FEDERATION) }
            .getOrElse { trustFail("cannot fetch the entity configuration of $entityId") }
    val statement = parseStatement(body)
    if (statement.issuer != entityId || statement.subject != entityId) {
        trustFail("entity configuration of $entityId has mismatched iss/sub")
    }
    return statement
}

internal fun fetchSubordinateStatement(
    fetcher: FederationFetcher,
    superiorConfiguration: EntityStatement,
    subject: String,
): EntityStatement {
    val endpoint =
        superiorConfiguration.federationFetchEndpoint
            ?: trustFail("${superiorConfiguration.subject} exposes no federation_fetch_endpoint")
    val url = "$endpoint?sub=${URLEncoder.encode(subject, StandardCharsets.UTF_8)}"
    val body =
        runCatching { fetcher.fetch(url) }
            .getOrElse { trustFail("cannot fetch the subordinate statement of $subject") }
    return parseStatement(body)
}

internal const val DEFAULT_MAX_CHAIN_LENGTH = 4

/**
 * Validates a trust chain ordered leaf-first (spec v1.4.5 §6.11): each statement's
 * signature is checked top-down starting from the out-of-band anchor keys, iss/sub
 * linking and temporal validity are enforced, and the leaf's credential signing keys
 * are returned.
 */
internal fun validateChain(
    chain: List<String>,
    expectedIssuer: String?,
    anchor: TrustAnchorConfig,
    clock: Clock,
    maxChainLength: Int = DEFAULT_MAX_CHAIN_LENGTH,
): List<JWK> {
    if (chain.size < 2) trustFail("a trust chain needs at least the leaf and an anchor statement")
    // The offline chain comes from an attacker-controlled header: bound it before any parsing.
    if (chain.size > maxChainLength) trustFail("trust chain longer than $maxChainLength statements")
    val statements = chain.map(::parseStatement)
    val leaf = statements.first()
    checkChainShape(statements, leaf, expectedIssuer, anchor)
    val now = clock.instant()
    var trustedKeys = anchor.federationKeys
    for (statement in statements.asReversed()) {
        if (now.isBefore(statement.issuedAt)) trustFail("statement of ${statement.subject} not yet valid")
        if (!now.isBefore(statement.expiresAt)) trustFail("statement of ${statement.subject} is expired")
        if (!verifiesWithAny(statement.jwt, trustedKeys)) {
            trustFail("signature of the statement about ${statement.subject} does not verify")
        }
        trustedKeys = statement.federationJwks.ifEmpty { trustedKeys }
    }
    val credentialKeys = leaf.credentialIssuerJwks.ifEmpty { leaf.federationJwks }
    if (credentialKeys.isEmpty()) trustFail("the leaf entity advertises no credential signing keys")
    return credentialKeys
}

private fun checkChainShape(
    statements: List<EntityStatement>,
    leaf: EntityStatement,
    expectedIssuer: String?,
    anchor: TrustAnchorConfig,
) {
    if (leaf.issuer != leaf.subject) trustFail("the leaf entity configuration is not self-issued")
    if (expectedIssuer != null && leaf.subject != expectedIssuer) {
        trustFail("credential iss does not match the trust chain leaf")
    }
    if (statements.last().issuer != anchor.entityId) {
        trustFail(
            "the chain does not end at the configured trust anchor ${anchor.entityId} " +
                "(chain ends at ${statements.last().issuer})",
        )
    }
    for (index in 1 until statements.size) {
        val expectedSubject = if (index == 1) leaf.subject else statements[index - 1].issuer
        if (statements[index].subject != expectedSubject) {
            trustFail("broken iss/sub linking at chain position $index")
        }
    }
}

private fun verifiesWithAny(
    jwt: SignedJWT,
    keys: List<JWK>,
): Boolean =
    keys.any { key ->
        runCatching { jwsVerifierFor(key)?.let(jwt::verify) == true }.getOrDefault(false)
    }

private fun jwsVerifierFor(key: JWK): JWSVerifier? =
    when (key.keyType) {
        KeyType.EC -> ECDSAVerifier(key.toECKey())
        KeyType.RSA -> RSASSAVerifier(key.toRSAKey())
        else -> null
    }
