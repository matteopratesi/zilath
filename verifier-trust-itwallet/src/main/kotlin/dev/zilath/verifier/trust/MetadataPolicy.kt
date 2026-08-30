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
     */
    fun resolve(
        metadata: Map<*, *>?,
        policies: List<Map<*, *>>,
    ): Map<String, Any?> {
        val merged = policies.fold(emptyMap<String, Map<String, Map<String, Any?>>>(), ::mergePolicy)
        val resolved = metadata.orEmpty().entries.associate { (type, section) -> type.toString() to section }
        return merged.entries.fold(resolved) { current, (type, typePolicy) ->
            val section = current[type] as? Map<*, *>
            current + (type to applyTypePolicy(type, section, typePolicy))
        }
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
                val cleaned = operators.entries.associate { (op, v) -> op.toString() to v }
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
                    else -> trustFail("unsupported metadata_policy operator $operator on $parameter")
                }
        }
        return merged
    }

    private fun validateOperators(
        parameter: String,
        operators: Map<String, Any?>,
    ) {
        operators.keys
            .firstOrNull { it !in SUPPORTED_OPERATORS }
            ?.let { trustFail("unsupported metadata_policy operator $it on $parameter") }
        ARRAY_OPERATORS
            .firstOrNull { operators.containsKey(it) && operators[it] !is List<*> }
            ?.let { trustFail("metadata_policy $it for $parameter must be an array") }
        if (operators.containsKey("essential") && operators["essential"] !is Boolean) {
            trustFail("metadata_policy essential for $parameter must be a boolean")
        }
        if (operators.containsKey("default") && operators["default"] == null) {
            trustFail("metadata_policy default for $parameter must not be null")
        }
        // OID-FED §6.1.3.1: one_of combines only with value, default and essential.
        if (operators.containsKey("one_of") &&
            operators.keys.any { it in setOf("add", "subset_of", "superset_of") }
        ) {
            trustFail("metadata_policy one_of for $parameter cannot combine with array operators")
        }
        // subset_of MAY combine with superset_of only when subset_of ⊇ superset_of.
        if (operators.containsKey("subset_of") &&
            operators.containsKey("superset_of") &&
            !asList(operators["subset_of"]).containsAll(asList(operators["superset_of"]))
        ) {
            trustFail("metadata_policy subset_of for $parameter must be a superset of superset_of")
        }
        if (operators.containsKey("value")) validateValueCombinations(parameter, operators)
    }

    /** OID-FED §6.1.3.1.1: `value` combines with the others under relationship checks. */
    private fun validateValueCombinations(
        parameter: String,
        operators: Map<String, Any?>,
    ) {
        val value = operators["value"]
        if (value == null && operators["essential"] == true) {
            trustFail("metadata_policy value null for $parameter cannot be essential")
        }
        if (value == null && operators.containsKey("default")) {
            trustFail("metadata_policy value null for $parameter cannot combine with default")
        }
        operators["one_of"]?.let {
            if (value !in asList(it)) trustFail("metadata_policy value for $parameter is not among one_of")
        }
        operators["subset_of"]?.let {
            if (!asList(it).containsAll(asList(value))) {
                trustFail("metadata_policy value for $parameter must be a subset of subset_of")
            }
        }
        operators["superset_of"]?.let {
            if (!asList(value).containsAll(asList(it))) {
                trustFail("metadata_policy value for $parameter must be a superset of superset_of")
            }
        }
        operators["add"]?.let {
            if (!asList(value).containsAll(asList(it))) {
                trustFail("metadata_policy add for $parameter must be a subset of value")
            }
        }
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
        operators["add"]?.let { result[parameter] = unionOf(result[parameter], it) }
        operators["default"]?.let { if (!result.containsKey(parameter)) result[parameter] = it }
        // Application order per OID-FED §6.1.3.1: the one_of check, then the subset_of
        // filter, then the superset_of check runs on the FILTERED value.
        operators["one_of"]?.let { allowed ->
            result[parameter]?.let { current ->
                if (current !in asList(allowed)) trustFail("metadata parameter $qualified violates one_of")
            }
        }
        operators["subset_of"]?.let { allowed ->
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
            val base = (result[type.toString()] as? Map<*, *>).orEmpty()
            result[type.toString()] =
                base.entries.associate { (k, v) -> k.toString() to v } +
                section.entries.associate { (k, v) -> k.toString() to v }
        }
        return result
    }

    private val SUPPORTED_OPERATORS =
        setOf("value", "add", "default", "one_of", "subset_of", "superset_of", "essential")

    private val ARRAY_OPERATORS = setOf("add", "one_of", "subset_of", "superset_of")
}

private fun unionOf(
    superior: Any?,
    subordinate: Any?,
): List<Any?> = (asList(superior) + asList(subordinate)).distinct()

private fun asList(value: Any?): List<Any?> =
    when (value) {
        null -> emptyList()
        is List<*> -> value
        else -> listOf(value)
    }
