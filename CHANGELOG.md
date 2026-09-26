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
moves with them. In three parts: `verifier-core` and the build; `verifier-trust-itwallet`;
`verifier-openid4vp` and the Spring starter. The demo application's own findings, the
receipt's `entitled` field and a guide for Spring Security are not part of this release.

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
  with a hostname, no userinfo, no IP literals except loopback, plain http only to the
  loopback names, for local development. A credential pointing anywhere else is
  `STATUS_CHECK_FAILED` before the status checker is called.
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

### Security — the trust chain (`verifier-trust-itwallet`)

- **The production IT-Wallet chain is trusted.** The anchor serves every subordinate one
  `metadata_policy` for five entity types, and it was applied to every type it named: the
  disability card issuer, which is no wallet provider, failed on `wallet_provider.jwks`
  "essential but absent", and no genuine card of it could verify. A policy, and a
  superior's statement metadata, now apply only to the entity types the leaf publishes
  (OpenID Federation §6.1.1, §3.1.1); policies are still validated for every type.
- **An issuer is trusted only for the credential types it lists**: the `vct` of every SD-JWT
  entry of its *resolved* `credential_configurations_supported`, so a superior's metadata or
  policy restricts them (IT-Wallet 1.4.6 §6.12.1). Any member, in any role, could publish
  signing keys and issue a disability card. A member that declares a type in its own
  configuration still can: trust marks, which would bind the role from above, are not
  checked.
- **Subordinate statements' `constraints` are enforced**: `max_path_length`,
  `naming_constraints` (excluded wins), `allowed_entity_types` (§6.2).
- **A trust chain has the shape §4 gives it.** Every statement after the leaf is a
  subordinate statement, the leaf's superior is one of its `authority_hints`, and
  `metadata_policy`, `metadata_policy_crit` or `constraints` in an entity configuration make
  the chain malformed. `[leaf, leaf, statement]` used to make the leaf its own superior. No
  entity appears twice in a chain (§17.1), and the online walk skips an authority hint it
  has already visited: a leaf that vouched for an entity of its own making, which vouched
  back, dropped the metadata the anchor's statement imposes. The leaf's configuration must
  verify with a key of its own `jwks` as well as with the one its superior attests, and the
  claims reserved to one kind of statement (`authority_hints`, `trust_marks` and the like
  for entity configurations, `source_endpoint` for subordinate statements) make the other
  kind malformed.
- **Each statement is verified only with the key its `kid` names**, and every attested key
  needs a unique `kid`.
- **`crit` fails the chain**, the library understanding no extension, and an operator named
  in `metadata_policy_crit` must be one the library implements.
- **The anchor's own configuration is verified before its fetch endpoint is used.**
- **A credential without `iss` is untrusted on the offline path too.**
- **A provided `trust_chain` is refreshed online**: its shape and anchor are checked, then
  the chain is resolved again and the fresh documents decide, so a statement the superior
  has withdrawn is a revocation. With `offlineFallback = true` the chain is refreshed along
  its own path one statement at a time, and only a document that cannot be fetched at all
  is taken from the header: the superiors are asked even when the leaf's own configuration
  cannot be fetched, so a withdrawn statement is missed only while the superior that
  withdrew it is unreachable. Subordinate statements valid for more than 24 hours are
  refused (`maxStatementLifetime`, IT-Wallet §6.11.1): that bounds how long a withdrawn
  statement can be replayed.
- A `null` metadata parameter, an array operator on a parameter that is not an array (`scope`,
  a space-separated list, counts as one, §6.1.3.1.8), and an `add` outside `subset_of` are
  policy errors, as the specification says.
- Every `Untrusted.reason` is a fixed phrase: none repeats an identifier or a name read
  from a document or a credential before any signature was checked.

### Security — what the trust evaluator now accepts that it refused

- An operator of `metadata_policy` the library does not implement is ignored unless it is
  critical (§6.1.3.2): the IT-Wallet 1.4.6 §6.9 example statement used to fail the chain.
- An entity statement `typ` in the long form, `application/entity-statement+jwt`.
- The anchor's own entity configuration closing a provided `trust_chain` (OID-FED §4) no
  longer counts towards `maxChainLength`, as it does not online: a leaf under two
  intermediates whose chain carried it was refused.

### Security — the flow and the starter (`verifier-openid4vp`, `verifier-spring-boot-starter`)

- **An outcome is read with a poll token, never with the transaction id.** The id is public
  by construction: it is in the QR code, in `state` and in the response URI. Anyone who saw
  a venue's screen could read the verified claims, and whoever started a same-device
  transaction and sent its link to someone else read that person's outcome once they came
  back (OpenID4VP 1.0 §14.2). `start()` returns a `PollToken` that travels nowhere a wallet
  or a bystander sees, the store keeps only its hash, and a wrong token reads `Unknown`, as a
  transaction that does not exist would. In same-device mode `consumeResponseCode` hands a
  fresh token to the user agent that came back with the code, and only that one reads.
- **Each response is encrypted to a key of its own transaction.** One long-lived key served
  every request object, so a response captured past a TLS terminator became readable the day
  that key leaked. Each transaction now publishes a P-256 key of its own, whose private half
  leaves the store with the response or when the transaction expires; a JWE `kid`, when there
  is one, must name it or the static key. A static key is only a fallback, and only when
  configured.
- **The same-device return ticket goes only to the call that recorded the outcome.** A second
  post of the same `access_denied` a cancelling wallet sends used to receive the same
  `response_code`, and anyone holding the id could burn it before the user's browser came
  back. It no longer depends on the store keeping the outcome bit for bit, nor on reading
  back through a replica. A rejected presentation gets no ticket: the page that started it
  reads pending, then expired.
- **Expiry is the flow's.** A transaction carries one `expiresAt`; every call checks it
  first and redacts an expired entry in place, and a verification that finishes after it is
  not recorded, so no outcome with claims is read past the time to live, whatever the store
  keeps: a verified outcome reads `Expired` from then on, a rejection keeps its reason without
  its detail, a wallet error its code without its description. In 0.3.0 a recorded outcome
  survived expiry. The in-memory store redacts an entry at its expiry and removes it a minute later,
  sweeping itself in the background by due time; it holds at most 10,000 transactions
  (`TooManyTransactionsException` beyond) and is closed with the flow.
- **A `vp_token` carries exactly one presentation**, under the query's id and no other key,
  as a JSON string; the bare string of pre-1.0 wallets only under `ArfBaselineProfile`. A
  request is read at construction: a DCQL query the library cannot evaluate is refused when
  the request is built instead of failing every response — one asking for more than one
  credential, one without `meta.vct_values` (which used to switch the credential type check
  off), a format other than `dc+sd-jwt` or the pre-1.0 `vc+sd-jwt`, `trusted_authorities`,
  or `require_cryptographic_holder_binding: false`. Its `claims` reach the verifier as
  `requestedClaims`.
- **What a wallet sends is bounded before it is kept or decoded**: the response (1 MiB,
  `maxWalletResponseLength`), its `error` (a token of 64 characters at most) and
  `error_description` (256 characters, printable ASCII). A `Transaction`, and a
  `DirectPostBody` (the wallet's POST), print neither secrets nor claims. A rejection's detail reaches the starter's log bounded, on one
  line. The time to live is capped at one hour.
- **The relying party's keys serve one purpose each**, under a `kid` of their own.
- **The entity configuration meets the production anchor's policy for verifiers**: it
  publishes `redirect_uris` (the same-device callback, when there is one), `vp_formats` and
  `authorization_encrypted_response_enc`
  alongside their current names, and `contacts`, now required. One parameter the policy marks
  essential, `authorization_signed_response_alg`, is left out on purpose: it would ask
  wallets to sign the response inside the JWE, a form the flow does not read. A
  cross-device-only relying party, which has no redirect, leaves out `redirect_uris` too, so
  it cannot satisfy that policy. The
  `trust_chain` of a request object is never sent expired, and can come from a
  `TrustChainSource`.
- **The starter** answers the wallet with the statuses IT-Wallet 1.4.6 §12.2.1.6.1
  tabulates, 403, 400 or 500, with a fixed description instead of the rejection reason; serves
  both endpoints with `Cache-Control: no-store` and whatever the wallet puts in `Accept`;
  serves the request object by POST too, with the wallet's `wallet_nonce` in it, and answers
  400 JSON for one that is not available, instead of a bare 404; configures an
  `openid_federation:` relying party (`zilath.openid4vp.federation.*`, and the entity
  configuration at `/.well-known/openid-federation`) and checks an `x509_hash:` client id
  against its certificate at startup; and uses the application's `TransactionStore`,
  `WalletProfile` and `TrustChainSource` beans when there are any.

### Breaking — the flow and starter API

- `awaitOutcome(txId)` is `awaitOutcome(txId, pollToken)`; `StartedTransaction` carries the
  `PollToken`; `consumeResponseCode` returns the reading token (`PollToken?`) instead of a
  `Boolean`.
- `handleWalletResponse` returns `HandledResponse(outcome, redirectUri)`;
  `sameDeviceRedirectFor` is gone.
- `Transaction` gains `expiresAt`, `pollTokenHash` and the transaction's key;
  `isExpired(now, ttl)` is `isExpired(now)`. `InMemoryTransactionStore(clock, ttl)` is
  `InMemoryTransactionStore(clock, maxTransactions)`; the store and the flow are
  `AutoCloseable`. Custom stores: the six properties the flow relies on are in the
  `TransactionStore` KDoc; `TransactionStoreContractTest` checks the first five (not
  retention). It is in the repository's test fixtures of `verifier-openid4vp`, not published
  to Maven Central.
- `RpKeys.responseEncryptionKey` is optional; `RpFederationConfig.contacts` is required;
  `WalletProfile`'s methods take the transaction's key. An `x509_hash:` client id without a
  matching `x5c` fails at construction.
- `PresentationRequest` throws for a DCQL query it cannot evaluate, including one without
  `meta.vct_values`, which 0.3.0 accepted and verified with no type check.
- The starter's HTTP answers change as described above, and its
  `response-encryption-key-jwk` property is optional (best left empty).
- `VerificationReceipts.issue(txId, request, verified)` is `issue(txId, request, outcome)`,
  with a `ReceiptOutcome`: `VERIFIED_ENTITLED`, `VERIFIED_NOT_ENTITLED` or `REJECTED`. The
  receipt's `entitled` is the caller's verdict on the disclosed claims, to be stated once its
  policy has run; it was a copy of `outcome`, so a card that verified without the
  entitlement was signed as one that had it.

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

- `FederationTrustEvaluator` takes `offlineFallback` (false) and `maxStatementLifetime`
  (24 hours); `FederationDocumentNotFoundException` is what a `FederationFetcher` throws for
  a document the server says does not exist, so that a withdrawn statement is told apart
  from an outage. **`TrustAnchorConfig` now requires a unique `kid` on every key**: copy the
  anchor's `jwks` as published.
- `RequestedClaims`, `RequestedClaim`, `ClaimPathSegment`, and
  `VerificationContext.requestedClaims`; `PresentationLimits` and
  `VerificationContext.presentationLimits`. Both are new constructor parameters with
  defaults: source-compatible, not binary-compatible.
- The production IT-Wallet federation documents, as served on 2026-09-24, in the test
  fixtures, with their provenance: the tests replay them with a fixed clock, and a card
  shaped as IT-Wallet 1.4.6 writes it is verified against them from one end to the other.

### Build

- The EUDI SD-JWT library's ktor HTTP client stack, 27 `io.ktor` modules Zilath never runs,
  is excluded from every published module and from the POMs; a check task fails the build
  if it comes back.
- CI actions are pinned by commit SHA, and a step refuses any that is not; Dependabot
  proposes updates for them. Not for the Gradle dependencies: it cannot regenerate the
  verification metadata below, so every pull request it opened would fail the build.
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
