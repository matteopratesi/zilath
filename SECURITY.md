# Security Policy

Zilath decides whether somebody gets something they are entitled to. A flaw here can let a
forged credential through, or turn a person away who had every right to be let in. Both
matter, and reports of either are welcome.

## Reporting a vulnerability

**Do not open a public issue, and do not describe the problem in a pull request.**

Use GitHub's private vulnerability reporting: the **Security** tab of this repository →
*Report a vulnerability*. It is private to the maintainer, and it gives you a place to
attach details without publishing them.

If that form is not available to you for any reason, write to the maintainer at the email
address on the commits in this repository (`git log -1 --format=%ae`). It is already public
by virtue of being in the git history, so using it exposes nothing further.

Please include, as far as you can:

- what an attacker achieves, not only what the code does wrong;
- the shortest sequence of steps that shows it — a failing test is the ideal form;
- which module and version, and whether the online or offline trust path is involved.

Never put the details in a public issue, a pull request, a discussion or a commit message,
not even partially. If you are unsure whether what you found counts as a vulnerability,
treat it as one and use a private channel: it is easy to move a report into the open later,
and impossible to move it back.

## What to expect

This is a side project maintained in evenings and weekends, so the honest numbers are:

- **acknowledgement within 7 days**;
- an assessment, with whether it is accepted and a rough timeline, **within 30 days**.

If a report is accepted you will be credited in the release notes and the commit, unless
you prefer not to be. If it is declined you will be told why, in enough detail to argue
back.

## Scope

The library modules are in scope: `verifier-core`, `verifier-openid4vp`,
`verifier-trust-itwallet`, `verifier-spring-boot-starter`.

`demo-checkout` is a demonstration application, **not** production software, and is
explicitly out of scope. Findings there are still welcome as ordinary issues. What it does
and does not do, so that nobody copies it for more than it is:

- Each transaction started from the demo pages is bound to the browser that started it, by a
  random session secret in a cookie (`HttpOnly`, `SameSite=Lax`, `Path=/demo`, `Secure`
  except over plain http on a loopback host). `/demo/wait`, `/demo/qr`,
  `/demo/authorize-url`, `/demo/status`, `/demo/ticket`, `/demo/receipt` and the
  same-device callback `/demo/cb` answer for it only the browser holding it, as IT-Wallet
  1.4.6 §12.2.1.7 asks of a relying party. Every transaction id the pages interpolate is
  HTML-escaped, and a path variable outside the transaction id alphabet is answered 404
  before the flow is asked.
- The conformance endpoints are separate. A transaction started through
  `/conformance/start` is not registered with the demo pages; after its same-device return
  the callback hands the returning user-agent the token that reads the outcome.
- The receipt is signed from the ticket page, once the demo's entitlement rule has been
  applied to the disclosed claims, and records that verdict.
- Its example `StatusChecker` answers `UNKNOWN`: the demo cannot check revocation, so every
  credential that carries a status reference is rejected.
- Trust on first use of the anchor's keys (`ZILATH_TRUST_ANCHOR_TOFU`) and disabled TLS
  checks (`ZILATH_INSECURE_TLS`) exist for the conformance tool's local, ephemeral anchor,
  and for nothing else.

## Boundaries the library does not defend

Stated up front, because a boundary you did not know about is the one that gets you. These
are not bugs; a report about them will be closed with a pointer here.

1. **Network destinations belong to your fetcher.** `FederationFetcher` and
   `StatusListFetcher` receive URLs derived from attacker-influenced content: entity
   identifiers and fetch endpoints read from federation documents not yet verified, and the
   status list URI a credential's issuer chose. The library holds both to one *shape* rule
   before either fetcher sees them — https with a hostname, no userinfo, no fragment, no IP
   literal or all-numeric host except loopback, plain http only to the loopback names —
   and a credential whose status list URI breaks it is rejected (`STATUS_CHECK_FAILED`)
   without a fetch. But the library never resolves names, so it cannot tell a legitimate
   host from one pointing into your network, nor from a name that some resolvers read as an
   address (`0x7f000001`). Timeouts, response size limits, redirect handling and
   private-range refusal are your implementation's responsibility.
2. **Transaction identifiers are public; poll tokens are not.** A transaction id is in the
   QR code, in `state`, in the request and response URIs and in the same-device link:
   anyone who sees the checkout's screen has it. It authorises posting to the OpenID4VP
   response endpoint, which is unauthenticated by protocol design. The first response to an
   open transaction records its outcome, whoever posts it, so anyone holding the id can end
   a transaction with an `error` before the wallet answers: a denial the protocol allows.
   The id never authorises reading an outcome. `awaitOutcome` takes the `PollToken` that
   `start()` returns to the checkout or, same-device, that `consumeResponseCode` hands the
   user-agent that came back; a wrong token reads `Unknown`, as a transaction that does not
   exist would. The flow keeps only the token's hash. Where the token lives — a server-side
   session, an HttpOnly cookie, never a URL or a log — and which browser a checkout page
   answers are the application's to decide.
3. **The default transaction store is in-memory** and single-process. It is not durable and
   not shared across nodes, and by default it holds at most 10,000 transactions: `start()`
   allocates one for whoever reaches the page that calls it, so rate-limit that page or bind
   it to a session. A clustered deployment needs its own `TransactionStore` — the starter
   uses the application's bean when there is one — with the properties listed in that
   interface's documentation.
4. **Trust anchors are yours to configure.** The library verifies chains against the anchor
   keys you give it. It has no opinion about which federation deserves that trust. Within
   the federation, an issuer is trusted for the credential types its metadata lists in
   `credential_configurations_supported`, after its superiors' `metadata_policy`. Trust
   marks are not checked, so a member in any role that lists a type in its own
   configuration is trusted for it, unless a superior's policy removes it. A `trust_chain`
   carried by a credential is refreshed online, so that a statement the superior has
   withdrawn counts as a revocation; with `offlineFallback = true`, a statement that cannot
   be fetched is taken from the chain, and a withdrawal is missed for as long as the
   superior that withdrew it cannot be reached.

## Production readiness

**0.3.0 cannot verify any genuine European Disability Card in the production IT-Wallet
configuration**: trust anchored to `https://ta.wallet.ipzs.it`, `FederationTrustEvaluator`
resolving the chain online, `ItWalletProfile`, `OAuthStatusListChecker`. The fourth
internal review ran that configuration twice, independently, against the real documents of
the IPZS federation, and every card of the issuer the anchor lists would have been refused.
The anchor's `metadata_policy` for wallet providers was applied to an issuer that publishes
no wallet provider metadata, so the chain ended untrusted; past that gate, a status list
token in the IT-Wallet form, which carries no `iss`, was refused. The regulatory piece is
missing as well — private relying parties are not yet admitted to verify the card in
production — but this failure did not depend on it, and would have remained once they are.

The code on `main`, not released at the time of writing, can verify such a card as far as
`verifier-trust-itwallet/src/test/kotlin/dev/zilath/verifier/trust/ProductionCedEndToEndTest.kt`
shows: a card shaped as IT-Wallet 1.4.6 writes it, with a Token Status List reference,
verified from one end to the other against the production federation documents as served on
2026-09-24, and the same card rejected once revoked in its list. That test does not show:

- **a card IPZS actually issued, or a real wallet.** Neither has been through the library.
  The card is synthetic. The federation's private keys are not ours, so the three documents
  are re-signed with substitute keys under their real `kid`s, every other claim unchanged
  (the trust decision on the untouched documents is `IpzsProductionChainTest`), and the
  status list token is one the test signs with the issuer's key: the issuer publishes no
  status list.
- **a card whose status is not a status list.** The issuer's entity configuration
  advertises a `status_assertion_endpoint` and a `status_attestation_endpoint`, not a status
  list. Only Token Status List is evaluated; a card whose `status` carries only an assertion
  or an attestation is rejected (`STATUS_CHECK_FAILED`, "status mechanism not supported").
  Which form the issuer's cards carry has not been observed.
- **a card that embeds its trust chain.** IT-Wallet lets an issuer put its `trust_chain` in
  the credential's header; that issuer's entity configuration alone is 39,668 characters,
  and Nimbus JOSE+JWT refuses any JOSE header over 20,000, a limit that is not configurable.
  Such a card is rejected (`MALFORMED`, "issuer JWT header exceeds the parser limit"). The
  test's card carries no chain, which is resolved online.

## Cryptographic review

The cryptography and trust chain have had four internal reviews, all by the maintainer.
After the first three every finding that concerned the library modules was fixed and is
covered by tests here; the two exceptions are named where they occur, and the design limits
deliberately left open are listed in `docs/privacy-by-design.md`:

- **2026-08-29** — an adversarial audit across the whole codebase, nine lenses with paired
  opposed reviewers. Of roughly 23 distinct findings, 21 were fixed; the remaining two
  were limits of the `gate-check` demo application, which has since been removed from the
  repository — they were not fixed, they left with the module.
- **2026-08-30** — a targeted review of signatures, encryption, hashing, nonces and the
  federation trust chain: every `main` source of the four library modules, read in full.
  Three findings, all fixed: an SSRF in the online trust-chain resolution, response-JWE
  confinement, and a missing clock tolerance on credential `exp`/`nbf`.
- **2026-09-02** — a third reading of the same, unchanged code, all four library modules in
  full, with two suspected findings tested against the running library rather than argued.
  Nothing cryptographic was wrong. What it found sat around the cryptography: the claims
  handed to the application still carried `iat`, `exp` and `nbf` — stable per credential and
  so a handle for linking two verifications of one person — while only `cnf` and `status`
  were being stripped; the rule refusing IP-literal hosts in the trust-chain walk missed the
  forms the JVM resolver accepts (`https://2130706433/` is 127.0.0.1); and a rejection
  `detail` passed through a dependency's exception message, harmless today only because that
  message happens to be null. All three fixed, each with a test that fails against the
  previous code. One design limit left open and documented: receipts are signed with the
  request-signing key (`docs/privacy-by-design.md`, known limits).

The fourth, from 2026-09-04 to 2026-09-24, read 0.3.0 and was the first to test it against
the real federation rather than against fixtures written by the same hands as the code:

- **What it used.** The documents of the production IT-Wallet federation — the IPZS trust
  anchor's entity configuration and subordinate list, its statement about the disability
  card issuer, that issuer's entity configuration — fetched with read-only GET requests and
  replayed unmodified. They are in the test fixtures of `verifier-core`, under
  `src/testFixtures/resources/dev/zilath/verifier/ipzs-2026-09-24/`, with their provenance.
- **How.** Seventeen lenses with a mandate each, two more where a completeness critic found
  the first pass thin (custom transaction stores; whether a genuine card verifies end to
  end). Every finding went through an adversarial judge that tried first to refute it, and
  the critical and high ones through a separate reproducer with a probe of its own. 83
  findings confirmed, 64 of them on an execution with its log; findings below high had, as a
  rule, no separate reproducer.
- **What it found**, among others: 0.3.0 verified no genuine disability card in the
  production configuration (above); a verification's outcome, claims included, could be
  read with the transaction id, which is in the QR code; `Verified` came back for a
  presentation that disclosed none of the claims asked for; an issuer was trusted for every
  credential type, whatever its role; a `trust_chain` carried by a credential was never
  refreshed, so a withdrawn issuer stayed trusted until the statements it carried expired;
  the status list URI reached the fetcher without the shape rule this file claimed for it.
  In the demo, out of scope, the ticket page showed a holder's name and entitlement to
  anyone who had the transaction id.
- **Where it stands.** The fixes are on `main`, not released at the time of writing; the
  changelog's *Unreleased* section lists them. What was left open is stated where it
  applies: the boundaries and the section on production readiness above, and the known
  limits in `docs/privacy-by-design.md`.

The reports themselves are working notes and are not published. **None of the four was
independent**: the same person wrote the code and audited it, which catches slips and
cannot catch blind spots. The fourth, like the ones before it, was conducted with model
assistance.

**There has been no external review.** Until there is, treat this library as promising
rather than proven, and say so to anyone who asks. If you are in a position to perform one,
that offer would be worth more to this project than any feature.
