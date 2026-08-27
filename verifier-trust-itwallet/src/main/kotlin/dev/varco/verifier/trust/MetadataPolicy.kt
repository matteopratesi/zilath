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

/*
 * OpenID Federation 1.0 §6.1 metadata policies (VARCO-34), the subset the IT-Wallet
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
                // Fail closed on anything outside the supported operator set (OID-FED
                // treats unknown critical operators as a resolution failure).
                cleaned.keys
                    .firstOrNull { it !in SUPPORTED_OPERATORS }
                    ?.let { trustFail("unsupported metadata_policy operator $it on $parameter") }
                typeResult[parameter.toString()] =
                    typeResult[parameter.toString()]?.let { mergeOperators(parameter.toString(), it, cleaned) }
                        ?: cleaned
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
                    "value", "default" -> equalOrFail(parameter, operator, merged[operator], value)
                    "add", "superset_of" -> unionOf(merged[operator], value)
                    "one_of", "subset_of" -> intersectionOrFail(parameter, operator, merged[operator], value)
                    "essential" -> (merged[operator] == true) || (value == true)
                    else -> trustFail("unsupported metadata_policy operator $operator on $parameter")
                }
        }
        return merged
    }

    private fun equalOrFail(
        parameter: String,
        operator: String,
        superior: Any?,
        subordinate: Any?,
    ): Any? {
        if (superior != null && superior != subordinate) {
            trustFail("conflicting metadata_policy $operator for $parameter")
        }
        return subordinate
    }

    private fun unionOf(
        superior: Any?,
        subordinate: Any?,
    ): List<Any?> = (asList(superior) + asList(subordinate)).distinct()

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
        if (operators.containsKey("value")) result[parameter] = operators["value"]
        operators["add"]?.let { result[parameter] = unionOf(result[parameter], it) }
        operators["default"]?.let { if (result[parameter] == null) result[parameter] = it }
        checkValueConstraints(qualified, operators, result, parameter)
        operators["subset_of"]?.let { allowed ->
            result[parameter]?.let { current ->
                val kept = asList(current).intersect(asList(allowed).toSet()).toList()
                if (kept.isEmpty()) result.remove(parameter) else result[parameter] = kept
            }
        }
        if (operators["essential"] == true && result[parameter] == null) {
            trustFail("metadata parameter $qualified is essential but absent")
        }
        return result
    }

    private fun checkValueConstraints(
        qualified: String,
        operators: Map<String, Any?>,
        result: Map<String, Any?>,
        parameter: String,
    ) {
        operators["one_of"]?.let { allowed ->
            result[parameter]?.let { current ->
                if (current !in asList(allowed)) trustFail("metadata parameter $qualified violates one_of")
            }
        }
        operators["superset_of"]?.let { required ->
            result[parameter]?.let { current ->
                if (!asList(current).containsAll(asList(required))) {
                    trustFail("metadata parameter $qualified violates superset_of")
                }
            }
        }
    }

    private val SUPPORTED_OPERATORS =
        setOf("value", "add", "default", "one_of", "subset_of", "superset_of", "essential")

    private fun asList(value: Any?): List<Any?> =
        when (value) {
            null -> emptyList()
            is List<*> -> value
            else -> listOf(value)
        }
}
