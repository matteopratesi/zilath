# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until 1.0.0 the public API may change between minor versions. Anything that changes what a
verifier accepts or rejects is called out explicitly, because that is the kind of change
that can silently let something through.

## [0.3.0] — 2026-09-01

A minor, not a patch: the first item below **removes claims that 0.2.0 returned**, and this
project's rule is that the API may move between minor versions until 1.0.0. A `0.2.1` would
have promised that nothing breaks.

### Security

Findings of the third internal review (2026-09-01). Each changes what a consumer receives or
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
