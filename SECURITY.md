# Security Policy

Zilath decides whether somebody gets something they are entitled to. A flaw here can let a
forged credential through, or turn a person away who had every right to be let in. Both
matter, and reports of either are welcome.

## Reporting a vulnerability

**Do not open a public issue, and do not describe the problem in a pull request.**

Use GitHub's private vulnerability reporting: the **Security** tab of this repository →
*Report a vulnerability*. It is private to the maintainer, and it gives you a place to
attach details without publishing them.

Please include, as far as you can:

- what an attacker achieves, not only what the code does wrong;
- the shortest sequence of steps that shows it — a failing test is the ideal form;
- which module and version, and whether the online or offline trust path is involved.

If you cannot use GitHub's form, open a normal issue saying only *"I have a security report
and need a private channel"* — with no details — and you will be given one.

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

`demo-checkout` and `gate-check` are demonstration applications, **not** production
software, and are explicitly out of scope — see their own documentation for the limits
they declare. Findings there are still welcome as ordinary issues.

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

The cryptography and trust chain have been reviewed internally, including an adversarial
audit whose findings are fixed. **They have not yet had an independent external review.**
Until they have, treat this library as promising rather than proven, and say so to anyone
who asks. If you are in a position to perform such a review, that offer would be more
valuable than any feature.
