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

import java.time.Instant
import kotlin.math.floor

/**
 * An RFC 7519 NumericDate claim as the JWT actually carries it.
 *
 * Read from the raw payload, never from Nimbus's `Date` getters: `DateUtils.fromSecondsSinceEpoch`
 * multiplies by 1000 in a `long` with no range check, so a large enough value wraps around to
 * any instant its author likes. The fourth internal review presented a key binding with
 * `iat = 18446745861275152`, which Nimbus turned into "a few hundred milliseconds ago", and
 * it passed the freshness window. The range is checked here, on the number, before anything
 * becomes an [Instant].
 */
internal sealed interface NumericDateClaim {
    /** The claim is not in the payload. */
    data object Absent : NumericDateClaim

    /** The claim is there but is not a number of seconds this side of year 10000. */
    data object Invalid : NumericDateClaim

    data class At(
        val instant: Instant,
    ) : NumericDateClaim
}

/**
 * The NumericDate [name] of [payload], a JWT payload as `Payload.toJSONObject()` returns it
 * (integers as `Long`, other numbers as `Double`).
 *
 * Valid is a whole or fractional number of seconds from 0 up to [MAX_NUMERIC_DATE]; a
 * fraction is dropped, as RFC 7519 §2 allows non-integer values. Anything else — negative,
 * beyond year 9999 (milliseconds are: a millisecond timestamp of today is year 57,000 read
 * as seconds), not a number, JSON null — is [NumericDateClaim.Invalid], and every caller
 * treats that as failure.
 */
internal fun numericDateClaim(
    payload: Map<String, Any?>,
    name: String,
): NumericDateClaim {
    if (!payload.containsKey(name)) return NumericDateClaim.Absent
    val seconds =
        when (val value = payload[name]) {
            is Long -> value.takeIf { it in 0..MAX_NUMERIC_DATE }
            is Int -> value.toLong().takeIf { it in 0..MAX_NUMERIC_DATE }
            is Double -> value.takeIf { it.isFinite() && it >= 0 && it <= MAX_NUMERIC_DATE }?.let { floor(it).toLong() }
            else -> null
        }
    return seconds?.let { NumericDateClaim.At(Instant.ofEpochSecond(it)) } ?: NumericDateClaim.Invalid
}

/** 9999-12-31T23:59:59Z, the largest instant any JWT this library reads can plausibly mean. */
private const val MAX_NUMERIC_DATE = 253_402_300_799L
