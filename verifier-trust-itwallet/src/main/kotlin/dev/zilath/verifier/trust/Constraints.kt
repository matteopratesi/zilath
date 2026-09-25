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

import java.net.URI
import java.util.Locale

/*
 * OpenID Federation 1.0 §6.2: the `constraints` a superior places on everything below it.
 * "The constraints Claim in each Subordinate Statement MUST be independently applied, if
 * present. If any of the constraints checks fails, the Trust Chain MUST be considered
 * invalid." Before the fourth internal review none was read: a member limited to
 * `max_path_length` 0 could still act as an intermediate and vouch for anyone, one limited
 * by `allowed_entity_types` could still publish credential signing keys, one limited by
 * `naming_constraints` could vouch outside its namespace. The production IT-Wallet anchor
 * sets a `max_path_length` on every statement it issues.
 */

/** One subordinate statement's constraints, parsed; unknown members are ignored. */
private class Constraints(
    val maxPathLength: Long?,
    val permitted: List<String>?,
    val excluded: List<String>?,
    /** `allowed_entity_types` and the IT-Wallet spelling `allowed_leaf_entity_types`, intersected. */
    val allowedEntityTypes: Set<String>?,
)

private fun constraintsOf(statement: EntityStatement): Constraints? {
    val claim = statement.constraints ?: return null
    // Membership, not nullness: a member present with the value null is a malformed signed
    // directive, not an absent one.
    val maxPathLength =
        if (claim.containsKey("max_path_length")) {
            (claim["max_path_length"] as? Long)?.takeIf { it >= 0 } ?: malformedConstraints()
        } else {
            null
        }
    val naming =
        if (claim.containsKey("naming_constraints")) {
            claim["naming_constraints"] as? Map<*, *> ?: malformedConstraints()
        } else {
            null
        }
    val allowedTypes =
        listOf("allowed_entity_types", "allowed_leaf_entity_types")
            .mapNotNull { name -> if (claim.containsKey(name)) stringsOrFail(claim[name]).toSet() else null }
            .reduceOrNull { acc, types -> acc intersect types }
    return Constraints(
        maxPathLength = maxPathLength,
        permitted = naming?.takeIf { it.containsKey("permitted") }?.let { stringsOrFail(it["permitted"]) },
        excluded = naming?.takeIf { it.containsKey("excluded") }?.let { stringsOrFail(it["excluded"]) },
        allowedEntityTypes = allowedTypes,
    )
}

private fun stringsOrFail(value: Any?): List<String> {
    val list = value as? List<*> ?: malformedConstraints()
    return list.map { it as? String ?: malformedConstraints() }
}

private fun malformedConstraints(): Nothing = trustFail("a subordinate statement carries malformed constraints")

/**
 * Applies `max_path_length` and `naming_constraints` of every statement in [subordinates]
 * (the leaf's immediate superior first).
 *
 * The statement at position k was issued by the entity k levels above the leaf's superior,
 * so k intermediates stand between its issuer and the leaf (§6.2.1): more than its
 * `max_path_length` fails. Its naming constraints bind the leaf and every intermediate
 * below its issuer, that is the subjects of statements 0..k (§6.2.2).
 */
internal fun checkPathAndNamingConstraints(subordinates: List<EntityStatement>) {
    subordinates.forEachIndexed { position, statement ->
        val constraints = constraintsOf(statement) ?: return@forEachIndexed
        constraints.maxPathLength?.let { limit ->
            if (position > limit) trustFail("the chain is longer than a superior's max_path_length allows")
        }
        if (constraints.permitted != null || constraints.excluded != null) {
            subordinates.subList(0, position + 1).forEach { below ->
                if (!satisfiesNamingConstraints(below.subject, constraints)) {
                    trustFail("an entity is outside a superior's naming constraints")
                }
            }
        }
    }
}

/**
 * RFC 5280 §4.2.1.10, the URI form, on the host of an entity identifier: a constraint that
 * starts with a period is a domain, satisfied by any host with one or more labels in front
 * of it (".example.com" admits "host.example.com", not "example.com"); any other
 * constraint names exactly one host. Comparison is case-insensitive, as DNS names are. An
 * excluded match wins over a permitted one; when `permitted` is present, a host must match
 * one of its entries — an empty list permits nothing. An identifier whose host cannot be
 * read satisfies nothing.
 */
private fun satisfiesNamingConstraints(
    entityId: String,
    constraints: Constraints,
): Boolean {
    val host = runCatching { URI(entityId).host }.getOrNull()?.lowercase(Locale.ROOT) ?: return false
    return constraints.excluded.orEmpty().none { hostMatches(host, it) } &&
        (constraints.permitted?.any { hostMatches(host, it) } ?: true)
}

private fun hostMatches(
    host: String,
    constraint: String,
): Boolean {
    val name = constraint.lowercase(Locale.ROOT)
    return if (name.startsWith(".")) host.endsWith(name) else host == name
}

/**
 * §6.2.3: removes from the leaf's [metadata] every entity type that a statement in
 * [subordinates] does not allow, except `federation_entity`, which is always allowed. It
 * runs after the immediate superior's metadata has been overlaid and before any policy,
 * so a forbidden type contributes nothing — least of all credential signing keys.
 */
internal fun withoutDisallowedEntityTypes(
    metadata: Map<String, Any?>,
    subordinates: List<EntityStatement>,
): Map<String, Any?> =
    subordinates
        .mapNotNull { constraintsOf(it)?.allowedEntityTypes }
        .fold(metadata) { current, allowed ->
            current.filterKeys { it == FEDERATION_ENTITY || it in allowed }
        }

private const val FEDERATION_ENTITY = "federation_entity"
