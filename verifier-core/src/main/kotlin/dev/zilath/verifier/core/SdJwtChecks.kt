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

import com.nimbusds.jwt.JWTClaimsSet

/*
 * Checks of the SD-JWT VC pipeline that need no state of the verifier: kept out of
 * [SdJwtVcCredentialVerifier] so that the class reads as the ORDER of the checks.
 */

/**
 * A trusted issuer is trusted for the credential types its trust decision names, not
 * for every type there is.
 *
 * Before the fourth internal review a federation leaf in ANY role — a relying party, the
 * PID provider, an issuer onboarded for health cards — could publish credential signing
 * keys and issue a disability card, and nothing tied the `vct` to the issuer: IT-Wallet
 * 1.4.6 §6.12.1 requires relying parties to check that the issuer "is allowed in the
 * issuance of the Credential of their interest". The check runs after the signature, on
 * the `vct` the issuer actually signed. A decision that names no types
 * ([TrustDecision.Trusted.credentialTypes] null) restricts nothing, which is what a
 * pinned-key evaluator means; an evaluator for a federation, where any member can publish
 * signing keys, has to name them.
 */
internal fun checkIssuerAuthorisedForType(
    issuerClaims: JWTClaimsSet,
    trusted: TrustDecision.Trusted,
) {
    val authorised = trusted.credentialTypes ?: return
    val vct = runCatching { issuerClaims.getStringClaim("vct") }.getOrNull()
    if (vct == null || vct !in authorised) {
        reject(RejectionReason.UNTRUSTED_ISSUER, "issuer is not authorised for this credential type")
    }
}
