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

import dev.zilath.verifier.core.ClaimPathSegment
import dev.zilath.verifier.core.RequestedClaim
import dev.zilath.verifier.core.RequestedClaims
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

/*
 * Reading a DCQL query (OpenID4VP 1.0 §6) into what the verifier checks.
 *
 * Everything here throws IllegalArgumentException on a query it cannot read, and it is
 * run when a PresentationRequest is constructed: a query this library cannot evaluate is
 * the relying party's own bug, and it must surface when the request is built — not as an
 * INTERNAL_ERROR at every wallet response, after the QR has already been shown.
 */

/**
 * The one Credential Query of [dcqlQuery], which must be named [credentialQueryId].
 *
 * One, because the response side verifies exactly one presentation: with a second query
 * in the request, or `credential_sets`, or `multiple`, the wallet would be asked for more
 * than the verifier then checks, and the rest of the response — present, absent or
 * garbage — would be ignored (OpenID4VP §8.6 wants every requirement of the request
 * checked). Until the flow evaluates §6.4.2 selection, such a query is refused.
 */
internal fun credentialQueryOf(
    dcqlQuery: JsonObject,
    credentialQueryId: String,
): JsonObject {
    val credentials =
        requireNotNull(dcqlQuery["credentials"] as? JsonArray) { "dcql_query has no credentials array" }
    require(credentials.size == 1) {
        "dcql_query must carry exactly one credential query: only that one is verified"
    }
    require("credential_sets" !in dcqlQuery) {
        "dcql_query credential_sets is not supported: only one credential query is verified"
    }
    val query =
        requireNotNull(credentials.single() as? JsonObject) { "dcql_query credential query is not an object" }
    require((query["id"] as? JsonPrimitive)?.takeIf { it.isString }?.content == credentialQueryId) {
        "dcql_query has no credential with id $credentialQueryId"
    }
    val multiple = query["multiple"]
    require(multiple == null || multiple.isJsonBoolean(false)) {
        "dcql_query multiple presentations are not supported: only one presentation is verified"
    }
    require((query["format"] as? JsonPrimitive)?.takeIf { it.isString }?.content in SD_JWT_VC_FORMATS) {
        "dcql_query format must be dc+sd-jwt (or the pre-1.0 vc+sd-jwt): only SD-JWT VC presentations are verified"
    }
    // Members that ask the wallet for something the response side would then not check. The
    // wallet would choose, or leave unbound, on the strength of a condition nobody verifies.
    require("trusted_authorities" !in query) {
        "dcql_query trusted_authorities is not supported: the issuer is judged by the TrustEvaluator"
    }
    val holderBinding = query["require_cryptographic_holder_binding"]
    require(holderBinding == null || holderBinding.isJsonBoolean(true)) {
        "dcql_query require_cryptographic_holder_binding must be true: every presentation needs its key binding"
    }
    return query
}

/** A JSON boolean of [value]: not the string "true", not a number. */
private fun JsonElement.isJsonBoolean(value: Boolean): Boolean =
    this is JsonPrimitive && !isString && booleanOrNull == value

/**
 * The credential formats a request may name. `dc+sd-jwt` is OpenID4VP 1.0's (Appendix
 * B.3.1). `vc+sd-jwt` is the identifier of the drafts before it, which wallets of those
 * drafts ask with: kept because what comes back is the same SD-JWT VC, verified the same
 * way, and the verifier accepts the `vc+sd-jwt` typ those credentials carry. Every other
 * format — mdoc, JWT or JSON-LD credentials — is one the verifier cannot read.
 */
private val SD_JWT_VC_FORMATS = setOf("dc+sd-jwt", "vc+sd-jwt")

/**
 * The credential types [credentialQuery] accepts, from `meta.vct_values`: never empty.
 *
 * OpenID4VP 1.0 makes `meta` REQUIRED in a Credential Query (§6.1) and `vct_values` REQUIRED
 * in it for SD-JWT VC (Appendix B.3.5), and the IT-Wallet conformance tool checks the RP
 * sends them (RPR-80). Here they are also what the credential type check reads: an empty
 * set switches it off. It used to be what a query without `meta`, with a `meta` that is not
 * an object, or with a misspelled `vct_value` produced — so any credential a trusted issuer
 * signed, of any type, answered the request. So each of those is refused, as is a blank type.
 */
internal fun vctValuesOf(credentialQuery: JsonObject): Set<String> {
    val meta = requireNotNull(credentialQuery["meta"] as? JsonObject) { "dcql_query meta must be an object" }
    val values = meta["vct_values"]
    require(values is JsonArray && values.isNotEmpty()) { "dcql_query meta.vct_values must be a non-empty array" }
    return values
        .map { value ->
            requireNotNull((value as? JsonPrimitive)?.takeIf { it.isString && it.content.isNotBlank() }?.content) {
                "dcql_query vct_values must hold non-blank strings"
            }
        }.toSet()
}

/**
 * The `claims` and `claim_sets` of [credentialQuery] as the verifier's [RequestedClaims]
 * (OpenID4VP 1.0 §6.3, §6.4.1, §7), or null when the query names no claims.
 */
internal fun requestedClaimsOf(credentialQuery: JsonObject): RequestedClaims? {
    val claims = credentialQuery["claims"]
    val claimSets = credentialQuery["claim_sets"]
    if (claims == null) {
        // §6.3: claim_sets MUST NOT be present when claims is absent.
        require(claimSets == null) { "dcql_query claim_sets needs a claims array" }
        return null
    }
    require(claims is JsonArray && claims.isNotEmpty()) { "dcql_query claims must be a non-empty array" }
    val requested = claims.map(::requestedClaimOf)
    val ids = requested.mapNotNull { it.id }
    // §6.3: within one claims array the same id MUST NOT appear twice.
    require(ids.size == ids.toSet().size) { "dcql_query claims ids must be unique" }
    return RequestedClaims(requested, claimSets?.let(::claimSetsOf))
}

private fun requestedClaimOf(element: JsonElement): RequestedClaim {
    val claim = requireNotNull(element as? JsonObject) { "dcql_query claims entries must be objects" }
    val path = requireNotNull(claim["path"] as? JsonArray) { "dcql_query claim has no path array" }
    val id =
        claim["id"]?.let { value ->
            val text = (value as? JsonPrimitive)?.takeIf { it.isString }?.content
            require(text != null && CLAIM_ID.matches(text)) { "dcql_query claim id is not a valid identifier" }
            text
        }
    val values =
        claim["values"]?.let { value ->
            require(value is JsonArray) { "dcql_query claim values must be an array" }
            value.map(::claimValueOf)
        }
    return RequestedClaim(path.map(::pathSegmentOf), id, values)
}

/** §7: a string names an object member, a non-negative integer an array index, null every element. */
private fun pathSegmentOf(element: JsonElement): ClaimPathSegment =
    when {
        element is JsonNull -> ClaimPathSegment.AllElements
        element is JsonPrimitive && element.isString -> ClaimPathSegment.Key(element.content)
        element is JsonPrimitive && element.booleanOrNull == null -> {
            // A JSON number: only an integer that fits an index is a path component. 1.0,
            // 1e3 and 2^31 are not "a non-negative integer" an array can be indexed with.
            val index = requireNotNull(element.content.toIntOrNull()) { "dcql_query path index is not an integer" }
            ClaimPathSegment.Index(index)
        }
        else -> throw IllegalArgumentException("dcql_query path component is not a string, integer or null")
    }

/** §6.3: `values` holds strings, integers or booleans — the values a claim is compared with. */
private fun claimValueOf(element: JsonElement): JsonPrimitive {
    val primitive =
        (element as? JsonPrimitive)?.takeIf {
            it !is JsonNull && (it.isString || it.booleanOrNull != null || it.longOrNull != null)
        }
    return requireNotNull(primitive) { "dcql_query claim values must be strings, integers or booleans" }
}

private fun claimSetsOf(element: JsonElement): List<List<String>> {
    require(element is JsonArray) { "dcql_query claim_sets must be an array" }
    return element.map { set ->
        require(set is JsonArray) { "dcql_query claim_sets entries must be arrays" }
        set.map { id ->
            requireNotNull((id as? JsonPrimitive)?.takeIf { it.isString }?.content) {
                "dcql_query claim_sets must name claim ids"
            }
        }
    }
}

/** §6.3: "alphanumeric, underscore (_), or hyphen (-) characters". */
private val CLAIM_ID = Regex("[A-Za-z0-9_-]+")
