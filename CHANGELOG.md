# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until 1.0.0 the public API may change between minor versions. Anything that changes what a
verifier accepts or rejects is called out explicitly, because that is the kind of change
that can silently let something through.

## [Unreleased]

The fixes of the fourth internal review (2026-09-04 to 2026-09-24), landing in parts. Headed
for 0.4.0, not a patch: many items change what a verifier accepts or rejects, and the API
moves with them. This part covers `verifier-core` and the build.

### Security — what the verifier now accepts that it refused

- **Status list tokens without `iss` are believed.** Neither draft-ietf-oauth-status-list
  nor IT-Wallet 1.4.6 requires `iss`, and the IT-Wallet example has none; every credential
  whose issuer followed it ended `STATUS_CHECK_FAILED`. The signature under the issuer's own
  keys binds the token to it; an `iss` that is present must still name the credential's
  issuer.
- **Credentials whose `_sd_alg` is `sha-384` or `sha-512` verify.** The key binding's
  `sd_hash` was recomputed in SHA-256 whatever `_sd_alg` said, on top of the EUDI library's
  own, correct check; the recomputation is gone.
- **`typ` values compare as RFC 7515 §4.1.9 says**: case-insensitively, with `application/`
  implied — `application/statuslist+jwt`, `DC+SD-JWT`, `application/kb+jwt` are the types
  they name. A different type, or one with parameters, is still refused.

### Security — what the verifier now refuses that it accepted

- **Weak keys verify nothing.** RSA keys below 2048 bits (RFC 7518 §3.3) and EC keys on any
  curve but P-256, P-384 and P-521 are skipped, for issuer, holder, status list and
  federation signatures alike: Nimbus enforces a minimum only when generating a key.
- **The status list URI is held to the URL rule** SECURITY.md already claimed for it: https
  with a hostname, no userinfo, no IP literals except loopback. A credential pointing
  anywhere else is `STATUS_CHECK_FAILED` before the status checker is called.
- **`Verified` means the query was answered.** With `VerificationContext.requestedClaims`, a
  presentation that does not disclose what was asked is `QUERY_NOT_SATISFIED` (OpenID4VP 1.0
  §6.3, §6.4.1, §7 claims path pointers); before, one disclosing nothing at all was
  verified.
- **Selective disclosure cannot hide the envelope.** A disclosure for `iss`, `nbf`, `exp`,
  `cnf`, `vct`, `vct#integrity`, `status` or `_sd_alg` is `MALFORMED` (SD-JWT VC §3.2.2.2):
  a `status` behind a disclosure used to skip revocation, an `exp` behind one never expired.
  Disclosures naming `_sd`, `...` or a non-string claim are `DISCLOSURE_TAMPERED` (RFC 9901
  §4.2.1).
- **A credential needs an `exp`**, and a plausible one: absent, in milliseconds, negative or
  more than fifty years ahead is `MALFORMED`. IT-Wallet 1.4.6 makes `exp` mandatory. Every
  date the verifier checks is read as a number and range-checked, since Nimbus's conversion
  to `Date` overflowed silently: an `iat` of 18446745861275152 passed the freshness window.
- **A key binding names exactly one audience**, ours. A list with another verifier beside us
  is `AUDIENCE_MISMATCH`; a one-element array naming us is accepted as the string.
- **A presentation is bounded before it is parsed** (`PresentationLimits`: 1 MiB, 256
  disclosures, nesting depth 32). Twelve megabytes of decoys used to verify, and a deeply
  nested disclosure under a trusted issuer's digest exhausted the heap.
- **An issuer is trusted for the types its trust decision names.** `TrustDecision.Trusted`
  gains `credentialTypes`; a credential whose `vct` is outside a non-null set is
  `UNTRUSTED_ISSUER`. Null restricts nothing, for pinned-key evaluators.

### Changed

- **`Verified.claims` is an allowlist.** Without a request: the claims the holder disclosed
  (a disclosed member of a plaintext object keeps its container, not its plaintext
  siblings), plus `iss` and `vct`. With a request: the requested claims that are present,
  plus `iss` and `vct`. **Issuer plaintext nobody asked for — `issuing_authority`,
  `issuing_country`, `verification`, `vct#integrity` on the disability card — is no longer
  returned: request it to receive it.** The envelope blocklist of 0.3.0 stays as a second
  filter, and the known limit it came with is gone.
- Status list values are reported as what they are: `0x02` is `CredentialStatus.SUSPENDED`
  (`RejectionReason.SUSPENDED`), any other non-zero value `APPLICATION_SPECIFIC`
  (`STATUS_NOT_VALID`), IT-Wallet's UPDATE and ATTRIBUTE_UPDATE among them. All of them still
  deny; only `0x01` is `REVOKED`.
- The status list's inflation cap is a constructor parameter, `maxInflatedBytes`, 16 MiB by
  default (134 million entries at `bits` 1, 16.7 million at `bits` 8). It was 1 MiB, a
  little over a million entries at `bits` 8. A token too long for any list under the cap is
  refused before it is parsed.
- A credential carrying only `status_assertion` or `status_attestation` is still rejected —
  only Token Status List is evaluated — but with its own detail, "status mechanism not
  supported".
- An issuer JWT header over Nimbus's 20,000-character limit is rejected with its own detail,
  "issuer JWT header exceeds the parser limit". The production disability card issuer's
  entity configuration alone is 39,668 characters: a credential of that issuer embedding its
  `trust_chain` in the header cannot be verified with Nimbus 10.3.
- The `detail` of an `UNTRUSTED_ISSUER` rejection, the one detail a `TrustEvaluator` writes,
  is cut to 200 characters with control characters and line separators replaced.
- Exceptions the EUDI library throws while rebuilding claims (`_sd` not an array, a
  disclosure colliding with a plaintext claim) no longer escape `verify()`: they are
  `DISCLOSURE_TAMPERED`.

### Added

- `RequestedClaims`, `RequestedClaim`, `ClaimPathSegment`, and
  `VerificationContext.requestedClaims`; `PresentationLimits` and
  `VerificationContext.presentationLimits`. Both are new constructor parameters with
  defaults: source-compatible, not binary-compatible.
- The production IT-Wallet federation documents, as served on 2026-09-24, in the test
  fixtures, with their provenance: the tests replay them with a fixed clock.

### Build

- The EUDI SD-JWT library's ktor HTTP client stack, 27 `io.ktor` modules Zilath never runs,
  is excluded from every published module and from the POMs; a check task fails the build
  if it comes back.
- CI actions are pinned by commit SHA, and a step refuses any that is not; Dependabot
  proposes updates for them and for the Gradle dependencies.
- The Gradle wrapper verifies the distribution's SHA-256.
- Every dependency and plugin is checked against the SHA-256 recorded in
  `gradle/verification-metadata.xml`: a changed or unknown artifact fails the build. The
  plugin repository is declared explicitly in `settings.gradle.kts`.

## [0.3.0] — 2026-09-02

A minor, not a patch: the first item below **removes claims that 0.2.0 returned**, and this
project's rule is that the API may move between minor versions until 1.0.0. A `0.2.1` would
have promised that nothing breaks.

### Security

Findings of the third internal review (2026-09-02). Each changes what a consumer receives or
what the library is willing to reach for:

- **The issuer envelope no longer reaches the application.** `Verified.claims` carried
  `iat`, `exp` and `nbf` alongside the disclosed claims — stable per credential, and so a
  handle for linking two verifications of the same person across venues and months. The
  registered envelope claims (`cnf`, `status`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`,
  `_sd_alg`) are now stripped; `iss` and `vct` are kept because they are identical for every
  holder of a credential type. **Code that read `iat` or `exp` from the claims will find them
  gone.** This is a blocklist: a claim an issuer places in the credential unprotected, under
  a name of its own, is still passed through — see the known limits in
  `docs/privacy-by-design.md`.
- **Numeric hosts are refused in the trust-chain walk.** `https://2130706433/…` passed the
  IP-literal check as a hostname and resolves to 127.0.0.1 on the JVM; `2851995650` lands in
  the link-local range. Any host made only of digits and dots is refused — no valid hostname
  has that shape.
- **Rejection details are fixed phrases.** The EUDI library's exception message is no longer
  passed through as `detail`: its disclosure errors carry the disclosures themselves, and the
  guarantee that `detail` holds no claim value has to hold by construction.
- A status list `idx` that does not fit an `Int` is malformed rather than silently truncated.

### Changed

- `RelyingPartyConfiguration` refuses a non-positive `transactionTimeToLive`.
- The request object and the federation entity configuration advertise the same SD-JWT
  algorithms (`ES256`, `ES384`, `ES512`); they used to disagree.

## [0.2.0] — 2026-09-01

First release published to Maven Central, under the name Zilath.

### Added

- **Same-device flow**: `FlowMode.SAME_DEVICE`, wallet acknowledgement carrying a
  `redirect_uri` with a single-use `response_code`, and `consumeResponseCode` for the
  return leg — including on wallet cancellation.
- **RP entity configuration**: the relying party publishes its own OpenID Federation entity
  configuration at `/.well-known/openid-federation`, and the request object carries the RP
  `trust_chain` header when the federation provides one.
- **`metadata_policy` support** (OpenID Federation §6.1): `value`, `add`, `default`,
  `one_of`, `subset_of`, `superset_of` and `essential`, merged anchor-first. Credential
  signing keys now come from the *resolved* metadata, so a superior can restrict what a
  leaf advertises.
- `ArfBaselineProfile` alongside `ItWalletProfile`, targeting EUDI wallets outside Italy.
- Signed verification receipts (`VerificationReceipts`).
- `CLA.md`, `CONTRIBUTING.md` and `SECURITY.md`.

### Security

Findings from an adversarial audit (2026-08-29) and a targeted cryptography and trust-chain
review (2026-08-30). Every item below could change a verification outcome:

- **Status list tokens were parsed but not verified.** The revocation check accepted any
  document served at the status URI, so whoever could answer that URL could make a revoked
  credential look valid. The token is now validated per draft-ietf-oauth-status-list §8.3:
  `typ`, signature against keys already trusted for the credential's issuer, `iss`, `sub`
  against the referenced URI, `exp`, and a required `iat` with a freshness window. Third-party
  status issuers are refused. Inflation is capped at 1 MiB and negative indices are rejected.
- **SSRF in the online trust-chain walk.** `federation_fetch_endpoint`, taken from a
  not-yet-verified superior, reached the injected fetcher unchecked. Every fetched URL now
  passes the same shape rules — https with a hostname, no userinfo, no IP literals except
  loopback — and `sub` is appended correctly to an endpoint that already carries a query.
- **Credential type was not checked.** A wallet could answer a request for one credential
  with a different one from the same trusted issuer. `VerificationContext.expectedVcts`,
  derived from the DCQL query, now makes "verified" mean "verified what you asked for".
- **`cnf` and `status` are stripped from the returned claims.** Both are stable per
  credential and would have let anything downstream link two verifications of the same
  person.
- **Response JWE confined** to the advertised `ECDH-ES` + AES-GCM, with compression refused.
- **Clock tolerance** of one minute on credential `exp`/`nbf`, matching the status list and
  trust chain checks.
- Transaction outcomes no longer leak through the same-device acknowledgement to a caller
  who did not produce them, and wallet-supplied error strings are bounded and stripped
  before reaching a log.

### Changed

- **Renamed to Zilath.** Group id is now `dev.zilath`, packages `dev.zilath.verifier.*`.
  Code written against `0.1.0` needs its imports updated.
- Target specification is IT-Wallet **v1.4.6 LTS**.
- `StatusChecker.check` takes a `StatusIssuerTrust` argument: a status answer is only worth
  the signature on it, so the checker needs to know which keys the issuer was trusted with.

### Removed

- **`gate-check`**, the self-hosted door tool. The operator established the outcome
  elsewhere — on the INPS service — and then recorded it here, so the signed receipt
  attested that somebody had entered a verdict, not that a check had taken place; and the
  module never called the library it shipped alongside. What it stood for, a receipt in
  place of a retained document, lives in `VerificationReceipts`, where the outcome comes
  from a verification the software performed. The code remains in the git history.

## [0.1.0] — 2026-08-24

First working version, released under the project's earlier name.

- SD-JWT VC verification: issuer signature, selective disclosure, key binding
  (audience, nonce, `iat` window, `sd_hash`), temporal validity, revocation.
- OpenID4VP cross-device flow, IT-Wallet profile: signed request object with DCQL,
  encrypted `direct_post.jwt` response, single-use nonce consumed atomically, TTL.
- OpenID Federation trust: provided `trust_chain` header or online resolution through
  `authority_hints`, validated top-down from out-of-band anchor keys.
- Spring Boot starter with the two wallet-facing endpoints; the core stays framework-free.
- Demo checkout application.
- The PagoPA conformance tool completes the cross-device happy flow against the library.
