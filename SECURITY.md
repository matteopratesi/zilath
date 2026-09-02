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
explicitly out of scope — see its own documentation for the limits it declares. Findings
there are still welcome as ordinary issues.

## Boundaries the library does not defend

Stated up front, because a boundary you did not know about is the one that gets you. These
are not bugs; a report about them will be closed with a pointer here.

1. **Network destinations belong to your fetcher.** `FederationFetcher` and
   `StatusListFetcher` receive URLs derived from attacker-influenced content. The library
   enforces their *shape* — https with a hostname, no userinfo, no IP literals except
   loopback — but it never resolves names, so it cannot tell a legitimate host from one
   pointing into your network. Timeouts, response size limits, redirect handling and
   private-range refusal are your implementation's responsibility.
2. **Transaction identifiers are bearer capabilities.** The OpenID4VP response endpoint is
   unauthenticated by protocol design. Whoever holds a transaction id can post to it. Keep
   them out of referrers, analytics and shipped logs.
3. **The default transaction store is in-memory** and single-process. It is not durable and
   not shared across nodes; a clustered deployment needs its own `TransactionStore`.
4. **Trust anchors are yours to configure.** The library verifies chains against the anchor
   keys you give it. It has no opinion about which federation deserves that trust.

## Cryptographic review

The cryptography and trust chain have had three internal reviews, all by the maintainer,
all with their findings fixed and covered by tests in this repository:

- **2026-08-29** — an adversarial audit across the whole codebase, nine lenses with paired
  opposed reviewers. Of roughly 23 distinct findings, 21 were fixed; the remaining two
  were limits of the `gate-check` demo application, which has since been removed from the
  repository — they were not fixed, they left with the module.
- **2026-08-30** — a targeted review of signatures, encryption, hashing, nonces and the
  federation trust chain: every `main` source of the four library modules, read in full.
  Three findings, all fixed: an SSRF in the online trust-chain resolution, response-JWE
  confinement, and a missing clock tolerance on credential `exp`/`nbf`.
- **2026-09-01** — a third reading of the same, unchanged code, all four library modules in
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

The reports themselves are working notes and are not published. **Neither review was
independent**: the same person wrote the code and audited it, which catches slips and
cannot catch blind spots.

**There has been no external review.** Until there is, treat this library as promising
rather than proven, and say so to anyone who asks. If you are in a position to perform one,
that offer would be worth more to this project than any feature.
