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

/*
 * OpenID Federation 1.0 §6.1 metadata policies, the subset the IT-Wallet
 * profile relies on: operators `value`, `add`, `default`, `one_of`, `subset_of`,
 * `superset_of`, `essential`. Policies from superior statements are merged anchor-first
 * and applied to the leaf metadata; any conflict or violation fails trust evaluation.
 */
internal object MetadataPolicy {
    /**
     * Resolves the leaf [metadata] against the [policies] of its superiors, ordered
     * anchor-first. Returns the resolved metadata (per metadata type).
     *
     * Every policy is merged and validated, for every entity type it names (OID-FED
     * §6.1.4.1: a policy error anywhere in the chain invalidates it), but a type's merged
     * policy is APPLIED only when the leaf publishes that type: §6.1.1 scopes a policy to
     * "Subordinate Entities of that type". Applying it to every type in the policy made
     * the production IT-Wallet anchor, whose single statement carries one policy for five
     * entity types with `wallet_provider.jwks` essential, reject its own disability card
     * issuer — which is not a wallet provider — and fabricated sections (via `default`,
     * `add`, `value`) that the leaf never published.
     *
     * [criticalOperators] is the union of the chain's `metadata_policy_crit`: operators the
     * superiors declared must be understood. Any other operator this library does not know
     * is ignored, as §6.1.3.2 requires.
     */
    fun resolve(
        metadata: Map<*, *>?,
        policies: List<Map<*, *>>,
        criticalOperators: Set<String> = emptySet(),
    ): Map<String, Any?> {
        requireCriticalOperatorsUnderstood(criticalOperators)
        val merged = policies.fold(emptyMap<String, Map<String, Map<String, Any?>>>(), ::mergePolicy)
        val resolved = metadata.orEmpty().entries.associate { (type, section) -> type.toString() to section }
        resolved.values.forEach(::requireWellFormedSection)
        return merged.entries.fold(resolved) { current, (type, typePolicy) ->
            val section = current[type] as? Map<*, *> ?: return@fold current
            current + (type to applyTypePolicy(type, section, typePolicy))
        }
    }

    /**
     * OID-FED §5: an entity type's metadata is a JSON object whose parameters may take any
     * JSON value except null. Nimbus keeps an explicit `null` member in nested objects, and
     * the policy operators used to read it two ways at once: present for `essential`
     * (containsKey), absent for `one_of` and `superset_of` (a null never compared) — so a
     * leaf could satisfy an essential parameter and dodge the check on its value by
     * publishing `"parameter": null`. It is a malformed document, and fails the chain.
     */
    private fun requireWellFormedSection(section: Any?) {
        if (section !is Map<*, *>) trustFail("a metadata section is not a JSON object")
        if (section.values.any { it == null }) trustFail("a metadata parameter is null")
    }

    /** Merges one superior's policy into the accumulated one (OID-FED §6.1.4). */
    private fun mergePolicy(
        accumulated: Map<String, Map<String, Map<String, Any?>>>,
        policy: Map<*, *>,
    ): Map<String, Map<String, Map<String, Any?>>> {
        val result = accumulated.toMutableMap()
        for ((type, parameters) in policy) {
            if (parameters !is Map<*, *>) trustFail("metadata_policy for $type is not an object")
            val typeResult = result[type.toString()].orEmpty().toMutableMap()
            for ((parameter, operators) in parameters) {
                if (operators !is Map<*, *>) trustFail("metadata_policy operators for $parameter are not an object")
                val cleaned = understoodOperators(operators.entries.associate { (op, v) -> op.toString() to v })
                validateOperators(parameter.toString(), cleaned)
                val merged =
                    typeResult[parameter.toString()]?.let { mergeOperators(parameter.toString(), it, cleaned) }
                        ?: cleaned
                // Cross-operator restrictions must hold for the COMBINED policy too.
                validateOperators(parameter.toString(), merged)
                typeResult[parameter.toString()] = merged
            }
            result[type.toString()] = typeResult
        }
        return result
    }

    private fun mergeOperators(
        parameter: String,
        superior: Map<String, Any?>,
        subordinate: Map<String, Any?>,
    ): Map<String, Any?> {
        val merged = superior.toMutableMap()
        for ((operator, value) in subordinate) {
            merged[operator] =
                when (operator) {
                    // A present `value: null` is a real directive (remove the parameter):
                    // presence is checked with containsKey, never by comparing to null.
                    "value", "default" -> {
                        if (merged.containsKey(operator) && merged[operator] != value) {
                            trustFail("conflicting metadata_policy $operator for $parameter")
                        }
                        value
                    }
                    "add", "superset_of" -> unionOf(merged[operator], value)
                    // one_of merges to the intersection and an empty result is a policy
                    // error; subset_of also merges to the intersection but [] is legal.
                    "one_of" -> intersectionOrFail(parameter, operator, merged[operator], value)
                    "subset_of" ->
                        merged[operator]
                            ?.let { asList(it).intersect(asList(value).toSet()).toList() }
                            ?: asList(value)
                    "essential" -> (merged[operator] == true) || (value == true)
                    // Unreachable: understoodOperators has dropped every other name.
                    else -> trustFail("unsupported metadata_policy operator")
                }
        }
        return merged
    }

    private fun intersectionOrFail(
        parameter: String,
        operator: String,
        superior: Any?,
        subordinate: Any?,
    ): List<Any?> {
        if (superior == null) return asList(subordinate)
        val intersection = asList(superior).intersect(asList(subordinate).toSet()).toList()
        if (intersection.isEmpty()) trustFail("empty metadata_policy $operator intersection for $parameter")
        return intersection
    }

    /** Applies the merged policy of one metadata type to its section (OID-FED §6.1.5). */
    private fun applyTypePolicy(
        type: String,
        section: Map<*, *>?,
        typePolicy: Map<String, Map<String, Any?>>,
    ): Map<String, Any?> {
        var result: Map<String, Any?> = section.orEmpty().entries.associate { (k, v) -> k.toString() to v }
        for ((parameter, operators) in typePolicy) {
            result = applyParameterPolicy("$type.$parameter", parameter, operators, result)
        }
        return result
    }

    private fun applyParameterPolicy(
        qualified: String,
        parameter: String,
        operators: Map<String, Any?>,
        section: Map<String, Any?>,
    ): Map<String, Any?> {
        val result = section.toMutableMap()
        if (operators.containsKey("value")) {
            // `value: null` means REMOVE the parameter, not set it to null.
            val forced = operators["value"]
            if (forced == null) result.remove(parameter) else result[parameter] = forced
        }
        operators["add"]?.let {
            requireArrayIfPresent(result, parameter)
            result[parameter] = unionOf(result[parameter], it)
        }
        operators["default"]?.let { if (!result.containsKey(parameter)) result[parameter] = it }
        // Application order per OID-FED §6.1.3.1: the one_of check, then the subset_of
        // filter, then the superset_of check runs on the FILTERED value.
        operators["one_of"]?.let { allowed ->
            result[parameter]?.let { current ->
                if (current !in asList(allowed)) trustFail("metadata parameter $qualified violates one_of")
            }
        }
        operators["subset_of"]?.let { allowed ->
            requireArrayIfPresent(result, parameter)
            if (result.containsKey(parameter)) {
                // An empty intersection is a legal resolved value: keep [] (it still
                // counts as present for `essential`).
                result[parameter] = asList(result[parameter]).intersect(asList(allowed).toSet()).toList()
            }
        }
        checkAfterShaping(qualified, parameter, operators, result)
        return result
    }

    private fun checkAfterShaping(
        qualified: String,
        parameter: String,
        operators: Map<String, Any?>,
        result: Map<String, Any?>,
    ) {
        operators["superset_of"]?.let { required ->
            requireArrayIfPresent(result, parameter)
            result[parameter]?.let { current ->
                if (!asList(current).containsAll(asList(required))) {
                    trustFail("metadata parameter $qualified violates superset_of")
                }
            }
        }
        if (operators["essential"] == true && !result.containsKey(parameter)) {
            trustFail("metadata parameter $qualified is essential but absent")
        }
    }

    /**
     * Overlays the immediate superior's subordinate-statement metadata onto the leaf's
     * (OID-FED §6.1: statement metadata takes precedence, per parameter, and is applied
     * BEFORE the merged policy).
     *
     * Only onto entity types the leaf publishes: OID-FED §3.1.1 says a subordinate
     * statement's metadata "applies only to those Entity Types that are present in the
     * subject's Entity Configuration". Grafting a whole section instead let a superior
     * turn an entity that is not a credential issuer — a relying party under the same
     * anchor — into one, `jwks` included, without that entity ever claiming the role.
     */
    fun overlay(
        leaf: Map<*, *>?,
        superior: Map<*, *>?,
    ): Map<String, Any?> {
        val result =
            leaf
                .orEmpty()
                .entries
                .associate { (k, v) -> k.toString() to v }
                .toMutableMap()
        for ((type, section) in superior.orEmpty()) {
            if (section !is Map<*, *>) trustFail("subordinate statement metadata for $type is not an object")
            val base = result[type.toString()] as? Map<*, *> ?: continue
            result[type.toString()] =
                base.entries.associate { (k, v) -> k.toString() to v } +
                section.entries.associate { (k, v) -> k.toString() to v }
        }
        return result
    }
}
