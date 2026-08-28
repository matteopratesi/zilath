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

/** Checks the revocation status of a credential against its status list reference. */
fun interface StatusChecker {
    /**
     * Resolves the revocation status referenced by [statusRef].
     *
     * Must not throw, and must never report [CredentialStatus.VALID] on doubt: anything
     * that goes wrong is [CredentialStatus.UNKNOWN], which the verifier treats as a
     * rejection. Failing closed is the point — a revoked credential that looks valid
     * because a fetch timed out is the one outcome this interface exists to prevent.
     */
    fun check(statusRef: StatusReference): CredentialStatus
}

/** The `status.status_list` reference carried by a credential. */
data class StatusReference(
    val uri: String,
    val index: Int,
)

/** The revocation state of a credential. Only [VALID] lets a verification succeed. */
enum class CredentialStatus {
    VALID,
    REVOKED,

    /** The status could not be determined (fetch failed, malformed list, ...). */
    UNKNOWN,
}
