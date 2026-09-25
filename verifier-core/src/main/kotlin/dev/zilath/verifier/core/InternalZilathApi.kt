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

/**
 * Marks a declaration that is public only so the other Zilath modules can share it.
 *
 * Kotlin's `internal` stops at the module boundary, and the rules these declarations
 * carry — which keys a signature may be checked with, which URLs may be dereferenced,
 * how a `typ` header compares — must be ONE rule across `verifier-core`,
 * `verifier-trust-itwallet` and `verifier-openid4vp`, not three copies that drift apart.
 * The fourth internal review found exactly that drift: the same key switch copied into two
 * modules with no strength check in either, and a URL shape rule that one module enforced
 * and the other did not.
 *
 * Not part of the supported API: signatures may change in any release, without notice.
 */
@RequiresOptIn(
    message = "Shared between Zilath modules; not part of the supported API.",
    level = RequiresOptIn.Level.ERROR,
)
@Retention(AnnotationRetention.BINARY)
@Target(AnnotationTarget.FUNCTION, AnnotationTarget.CLASS, AnnotationTarget.PROPERTY)
annotation class InternalZilathApi
