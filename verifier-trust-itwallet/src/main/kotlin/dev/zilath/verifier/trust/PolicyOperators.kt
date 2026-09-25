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
 * The operators of OpenID Federation 1.0 §6.1.3 as [MetadataPolicy] understands them:
 * which ones exist, what their operands must be, which combinations are legal. Kept apart
 * from the merge and the application so each file reads as one of the three steps.
 */

internal val SUPPORTED_OPERATORS =
    setOf("value", "add", "default", "one_of", "subset_of", "superset_of", "essential")

/** Operators whose operand must be a JSON array. */
private val ARRAY_OPERATORS = setOf("add", "one_of", "subset_of", "superset_of")

/** Operators that work on an array-valued PARAMETER; `one_of` picks a single value. */
private val ARRAY_PARAMETER_OPERATORS = setOf("add", "subset_of", "superset_of")

/**
 * Fails the chain unless [operators], one parameter's policy, is legal on its own. Called
 * on each superior's policy AND on the merged one: a combination that no single superior
 * wrote can still arise from two of them, and it must fail the same way (§6.1.4.1).
 */
internal fun validateOperators(
    parameter: String,
    operators: Map<String, Any?>,
) {
    validateOperands(parameter, operators)
    validateCombinations(parameter, operators)
    if (operators.containsKey("value")) {
        validateValueShape(parameter, operators)
        validateValueRelationships(parameter, operators)
    }
}

private fun validateOperands(
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
}

private fun validateCombinations(
    parameter: String,
    operators: Map<String, Any?>,
) {
    // OID-FED §6.1.3.1: one_of combines only with value, default and essential.
    if (operators.containsKey("one_of") && operators.keys.any { it in ARRAY_PARAMETER_OPERATORS }) {
        trustFail("metadata_policy one_of for $parameter cannot combine with array operators")
    }
    // subset_of MAY combine with superset_of only when subset_of ⊇ superset_of.
    if (operators.containsKey("subset_of") &&
        operators.containsKey("superset_of") &&
        !asList(operators["subset_of"]).containsAll(asList(operators["superset_of"]))
    ) {
        trustFail("metadata_policy subset_of for $parameter must be a superset of superset_of")
    }
    // §6.1.3.1.2: add MAY combine with subset_of only when add ⊆ subset_of. Because this
    // runs on the MERGED operators too, an anchor's subset_of [ES256] followed by an
    // intermediate's add [RS256] is the policy error the spec says it is, not a chain
    // that quietly resolves to [ES256].
    if (operators.containsKey("add") &&
        operators.containsKey("subset_of") &&
        !asList(operators["subset_of"]).containsAll(asList(operators["add"]))
    ) {
        trustFail("metadata_policy add must be a subset of subset_of")
    }
}

/** OID-FED §6.1.3.1.1: what a forced `value` may look like next to the other operators. */
private fun validateValueShape(
    parameter: String,
    operators: Map<String, Any?>,
) {
    val value = operators["value"]
    // add, subset_of and superset_of are array operators (§6.1.3.1.2/.5/.6): a value
    // they combine with must be an array too, or removal (null).
    if (value != null && value !is List<*> && operators.keys.any { it in ARRAY_PARAMETER_OPERATORS }) {
        trustFail("metadata_policy value combined with an array operator must be an array")
    }
    if (value == null && operators["essential"] == true) {
        trustFail("metadata_policy value null for $parameter cannot be essential")
    }
    if (value == null && operators.containsKey("default")) {
        trustFail("metadata_policy value null for $parameter cannot combine with default")
    }
}

/** OID-FED §6.1.3.1.1: a forced `value` must satisfy every operator it is combined with. */
private fun validateValueRelationships(
    parameter: String,
    operators: Map<String, Any?>,
) {
    val value = operators["value"]
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

/**
 * OID-FED §6.1.3: an operator applied to a parameter of a JSON type it does not support
 * MUST produce a policy error. The array operators used to wrap a string or an object
 * into a one-element list and carry on, silently changing its type — `subset_of` on
 * `jwks` turned the key set into a list, and the chain then failed with a misleading
 * "no credential signing keys".
 */
internal fun requireArrayIfPresent(
    section: Map<String, Any?>,
    parameter: String,
) {
    val current = section[parameter]
    if (current != null && current !is List<*>) {
        trustFail("a metadata_policy array operator applies to a parameter that is not an array")
    }
}

internal fun unionOf(
    superior: Any?,
    subordinate: Any?,
): List<Any?> = (asList(superior) + asList(subordinate)).distinct()

internal fun asList(value: Any?): List<Any?> =
    when (value) {
        null -> emptyList()
        is List<*> -> value
        else -> listOf(value)
    }
