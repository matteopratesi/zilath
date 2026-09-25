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
 * OID-FED 1.0 §6.1.3.1.8: "The scope OAuth 2.0 client metadata parameter, defined in
 * [RFC7591] and represented by a string of space-separated string values, is to be regarded
 * and processed as a string array by policy operators", and the resolved `scope` is a
 * space-separated string again. Treated like any other string it was refused by the array
 * operators as "not an array", failing a chain the specification calls valid.
 */

private const val SCOPE = "scope"

/** [value] as the array of its scope values when [parameter] is `scope` and [value] a string. */
internal fun asScopeArray(
    parameter: String,
    value: Any?,
): Any? = if (parameter == SCOPE && value is String) value.split(' ').filter { it.isNotEmpty() } else value

/** A resolved `scope` back to its space-separated form; any other parameter as it is. */
internal fun asScopeString(
    parameter: String,
    value: Any?,
): Any? = if (parameter == SCOPE && value is List<*>) value.joinToString(" ") else value

/** The `value` and `default` of a `scope` policy, written as strings, as arrays like the rest. */
internal fun withScopeOperandsAsArrays(
    parameter: String,
    operators: Map<String, Any?>,
): Map<String, Any?> =
    operators.mapValues { (operator, operand) ->
        if (operator == "value" || operator == "default") asScopeArray(parameter, operand) else operand
    }
