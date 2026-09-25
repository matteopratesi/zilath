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

import kotlinx.serialization.json.JsonPrimitive

/**
 * What a request asked the holder to disclose from one credential: the `claims` and
 * `claim_sets` of a DCQL Credential Query (OpenID4VP 1.0 §6.3, §6.4.1), carried into
 * verification through [VerificationContext.requestedClaims].
 *
 * Kept free of DCQL's JSON so that the verifier does not depend on the protocol layer:
 * `verifier-openid4vp` builds it from the query, any other caller builds it by hand.
 */
data class RequestedClaims(
    val claims: List<RequestedClaim>,
    /**
     * The acceptable combinations of [RequestedClaim.id]s, in the verifier's order of
     * preference. Null means every entry of [claims] is required.
     */
    val claimSets: List<List<String>>? = null,
) {
    init {
        require(claims.isNotEmpty()) { "requested claims must name at least one claim" }
        // DCQL makes an id unique within its claims (OpenID4VP 1.0 §6.3). Checked here as well
        // as by the query parser because this type is public and built by hand too: two claims
        // sharing an id, one satisfied and one not, would let a claim set naming that id pass.
        val declaredIds = claims.mapNotNull { it.id }
        require(declaredIds.size == declaredIds.toSet().size) { "claim ids must be unique" }
        claimSets?.let { sets ->
            require(sets.isNotEmpty()) { "claim_sets must not be empty when present" }
            require(sets.none { it.isEmpty() }) { "a claim set must name at least one claim" }
            val ids = claims.mapNotNull { it.id }.toSet()
            require(claims.all { it.id != null }) { "every claim needs an id when claim_sets is present" }
            require(sets.flatten().all { it in ids }) { "a claim set names an id no claim has" }
        }
    }
}

/** One entry of a DCQL `claims` array. */
data class RequestedClaim(
    /** The claims path pointer (OpenID4VP 1.0 §7): from the top-level claim inward. */
    val path: List<ClaimPathSegment>,
    val id: String? = null,
    /**
     * The values the claim may take; null means any value. Compared in type and value with
     * each element [path] selects, and satisfied when one of them matches: a path ending in
     * [ClaimPathSegment.AllElements] asks whether any element of the array is one of these,
     * while a path that selects the array itself never matches, since an array is not a
     * string, number or boolean.
     */
    val values: List<JsonPrimitive>? = null,
) {
    init {
        require(path.isNotEmpty()) { "a claims path must not be empty" }
        require(path.first() is ClaimPathSegment.Key) { "a claims path starts with a claim name" }
        values?.let { require(it.isNotEmpty()) { "values must not be empty when present" } }
    }
}

/** A component of a claims path pointer (OpenID4VP 1.0 §7). */
sealed interface ClaimPathSegment {
    /** A JSON string: the member of that name in an object. */
    data class Key(
        val name: String,
    ) : ClaimPathSegment

    /** A non-negative JSON integer: the element at that index in an array. */
    data class Index(
        val index: Int,
    ) : ClaimPathSegment {
        init {
            require(index >= 0) { "a claims path index must not be negative" }
        }
    }

    /** JSON `null`: every element of an array. */
    data object AllElements : ClaimPathSegment
}
