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

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/*
 * What a verified presentation hands to the application: [VerificationResult.Verified.claims].
 *
 * An allowlist, in both modes. Without a request, the paths the holder disclosed; with one,
 * the requested paths that are present. Plus `iss` and `vct` in either case — they name the
 * issuer and the credential type, are the same for every holder of that type, and say what
 * was verified. Then [ENVELOPE_CLAIMS] is removed again, as a second, defensive filter.
 *
 * Before the fourth internal review this was a blocklist: the recreated claims minus the
 * envelope. Everything else survived — an issuer's plaintext claim under a name of its own
 * invention, stable per credential and so a key for linking two verifications, and whatever
 * surplus a wallet disclosed beyond the request. The blocklist was recorded as a known limit
 * because telling disclosed claims from issuer plaintext seemed to need an unsettled nested
 * case; the EUDI library already reports, per path, which disclosures put it there
 * ([RecreatedClaims.disclosedPaths]), nested members included.
 */

/**
 * The claims [VerificationResult.Verified] carries for [recreated], given what the request
 * asked for. Rejects with [RejectionReason.QUERY_NOT_SATISFIED] when [requested] is not
 * satisfied: see [VerificationContext.requestedClaims].
 */
internal fun outcomeClaims(
    recreated: RecreatedClaims,
    requested: RequestedClaims?,
): JsonObject {
    val kept = if (requested == null) recreated.disclosedPaths else satisfiedPaths(recreated.claims, requested)
    // The root is never a kept path: keeping it would keep everything.
    val allowed = kept.filter { it.isNotEmpty() }.toSet() + ALWAYS_KEPT.map { listOf(ClaimPathSegment.Key(it)) }
    val pruned =
        pruned(recreated.claims, emptyList(), allowed, ancestorsOf(allowed)) as? JsonObject ?: JsonObject(emptyMap())
    return JsonObject(pruned.filterKeys { it !in ENVELOPE_CLAIMS })
}

/**
 * The concrete paths of the requested claims that are satisfied, after checking that a
 * combination [RequestedClaims.claimSets] allows (without `claim_sets`: all of them) is.
 *
 * A requested claim is satisfied when its path selects at least one element and, if it
 * names [RequestedClaim.values], at least one selected element equals one of them in type
 * and value (OpenID4VP 1.0 §6.3). Issuer plaintext satisfies a request as well as a
 * disclosure does: the credential answers the question either way. Only the selected
 * elements that match `values` are kept — a claim present with another value is left out of
 * the outcome, so presence there always means the value is one of those asked for — and a
 * satisfied claim outside the combination that decided is still requested, and kept.
 */
private fun satisfiedPaths(
    claims: JsonObject,
    requested: RequestedClaims,
): Set<ConcretePath> {
    val satisfied =
        requested.claims.map { claim ->
            val paths =
                selectionOf(claims, claim.path)
                    // JSON equality is type and value, as §6.3 asks: true is not "true", 1 is not "1".
                    ?.filter { (_, element) -> claim.values == null || claim.values.any { it == element } }
                    ?.map { (path, _) -> path }
                    .orEmpty()
            claim to paths
        }
    val satisfiedIds =
        satisfied
            .filter { (_, paths) ->
                paths.isNotEmpty()
            }.mapNotNull { (claim, _) -> claim.id }
            .toSet()
    val answered =
        requested.claimSets?.any { set -> set.all { it in satisfiedIds } }
            ?: satisfied.all { (_, paths) -> paths.isNotEmpty() }
    if (!answered) {
        reject(RejectionReason.QUERY_NOT_SATISFIED, "presentation does not disclose what was requested")
    }
    return satisfied.flatMap { (_, paths) -> paths }.toSet()
}

/**
 * OpenID4VP 1.0 §7, claims path pointer processing: from the root, a string selects that
 * member of every selected element, a non-negative integer that index, null every element
 * of every selected array. A selected element of the wrong kind for the next component —
 * not an object for a string, not an array for an index or null — is an error, and so is
 * an empty selection at the end; both return null. A member or index missing from one
 * selected element only drops that element.
 */
private fun selectionOf(
    claims: JsonObject,
    pointer: List<ClaimPathSegment>,
): List<Pair<ConcretePath, JsonElement>>? {
    val root: List<Pair<ConcretePath, JsonElement>>? = listOf(emptyList<ClaimPathSegment>() to claims)
    return pointer.fold(root) { selected, segment -> selected?.let { selectedNext(it, segment) } }?.ifEmpty { null }
}

/** One component of [selectionOf]: the next selection, or null for an error. */
private fun selectedNext(
    selected: List<Pair<ConcretePath, JsonElement>>,
    segment: ClaimPathSegment,
): List<Pair<ConcretePath, JsonElement>>? =
    when (segment) {
        is ClaimPathSegment.Key ->
            selected.takeIf { all -> all.all { it.second is JsonObject } }?.mapNotNull { (path, element) ->
                (element as JsonObject)[segment.name]?.let { path + segment to it }
            }
        is ClaimPathSegment.Index ->
            selected.takeIf { all -> all.all { it.second is JsonArray } }?.mapNotNull { (path, element) ->
                (element as JsonArray).getOrNull(segment.index)?.let { path + segment to it }
            }
        ClaimPathSegment.AllElements ->
            selected.takeIf { all -> all.all { it.second is JsonArray } }?.flatMap { (path, element) ->
                (element as JsonArray).mapIndexed { index, child -> path + ClaimPathSegment.Index(index) to child }
            }
    }

/** Every proper prefix of [paths], the empty root included: the containers to keep. */
private fun ancestorsOf(paths: Set<ConcretePath>): Set<ConcretePath> =
    paths.flatMapTo(mutableSetOf()) { path -> (0 until path.size).map { path.subList(0, it) } }

/**
 * [element] at [path] cut down to what [kept] allows: whole if [path] is kept, rebuilt from
 * its kept members if it contains one, null otherwise. An array keeps its kept elements in
 * their order and loses the rest: removed, not replaced — a placeholder would be a value the
 * credential never had, and indices are not stable across presentations anyway (the
 * recreated array has already lost every element the holder withheld).
 */
private fun pruned(
    element: JsonElement,
    path: ConcretePath,
    kept: Set<ConcretePath>,
    ancestors: Set<ConcretePath>,
): JsonElement? =
    when {
        path in kept -> element
        path !in ancestors -> null
        element is JsonObject ->
            JsonObject(
                element.entries
                    .mapNotNull { (name, child) ->
                        pruned(child, path + ClaimPathSegment.Key(name), kept, ancestors)?.let { name to it }
                    }.toMap(),
            )
        element is JsonArray ->
            JsonArray(
                element.mapIndexedNotNull { index, child ->
                    pruned(child, path + ClaimPathSegment.Index(index), kept, ancestors)
                },
            )
        else -> null
    }

/**
 * `iss` and `vct`: always part of the outcome. Both are in plaintext by construction — a
 * disclosed one is refused (`checkEnvelopeIsPlaintext`).
 */
private val ALWAYS_KEPT = listOf("iss", "vct")

/**
 * The issuer envelope: every RFC 7519 registered claim that dates or identifies the
 * credential, plus the SD-JWT VC machinery. Never part of an outcome, even when requested:
 * `cnf` is the holder's key and `status` the credential's slot in its issuer's revocation
 * list, and `iat`, `exp`, `nbf`, `jti`, `sub` are just as stable per credential — an
 * issuance instant at second granularity, with `iss` and `vct`, singles out one credential
 * almost as surely as a serial number would. Handing any of them over would let an
 * integrator, or anything downstream, link two verifications of the same person across
 * venues and across months (third internal review). The allowlist already keeps them out
 * unless a holder disclosed one or a request named one; this removes them regardless.
 */
private val ENVELOPE_CLAIMS = setOf("cnf", "status", "sub", "aud", "exp", "nbf", "iat", "jti", "_sd_alg")
