# Contributing to Zilath

Thank you for considering it. This is a small project with a specific purpose: letting a
person prove an entitlement — a companion ticket, priority access — without sending
anybody their medical paperwork. Everything below follows from that.

**Found a security problem? Do not open an issue.** See [SECURITY.md](SECURITY.md).

## Before you write code

Open an issue first for anything beyond a typo or an obvious bug fix. Two reasons: the
project has red lines that are not obvious from the code alone (below), and it is a
side project — a large pull request nobody asked for may wait a long time, which is a
waste of your evening as much as mine.

## The red lines

These are not style preferences. A contribution that crosses one will be declined however
good the code is:

1. **No credential is ever stored.** A presentation is verified and discarded. What
   survives a transaction is its own bookkeeping and the disclosed attributes the caller
   asked for — nothing else, and not for longer than the transaction.
2. **No profiling, ever.** No per-person counters, no history, no identifiers that let two
   verifications be linked. Not even to prevent abuse.
3. **Never fail open.** Anything uncertain — a fetch that timed out, a signature that will
   not verify, a claim that does not parse — is a rejection, never an acceptance. If you
   find yourself writing `runCatching { … }.getOrDefault(somethingPermissive)` in a
   verification path, that is the bug.
4. **The person being verified never pays and is never metered.**

## Building

```bash
./gradlew clean build
```

That runs everything CI runs: compilation, tests, `ktlint`, `detekt`, coverage. Use
`clean build` rather than `build` after changing anything in `verifier-core` — an
incremental build can go green while a clean one does not, because dependent modules are
not always recompiled when a signature changes.

To run one module's tests:

```bash
./gradlew verifier-openid4vp:test
```

## What a good change looks like

- **Tests that can fail.** Before you trust a new test, break the thing it guards and
  watch it go red. A test that passes with the guard removed is testing nothing, and this
  project has shipped one before.
- **Comments that say why, not what.** The code says what it does. A comment earns its
  place by recording the reason a check exists, the attack it closes, or the specification
  clause it implements — including the section number.
- **Specification references.** When behaviour comes from OpenID4VP, IT-Wallet,
  OpenID Federation or the status list draft, cite the section. `docs/spec-version.md`
  records which versions this library targets.
- **Small.** One concern per pull request.

## Style

Kotlin, formatted by `ktlint`, checked by `detekt`; both run in `build`. Every source file
carries the AGPL header — copy it from any existing file.

**Comments and identifiers in English**, including in tests. Test names are sentences
describing the behaviour, in backticks.

Commit messages: a short imperative summary line, then paragraphs explaining *why*, wrapped
at 80 columns. No AI co-author trailers.

## Signing off

Contributions require agreement to the [Contributor License Agreement](CLA.md). Read it —
it is short, and section 4 lists what the project commits to in return.

Sign your commits off with:

```bash
git commit -s
```

## Reviews

Pull requests get an automated review before a human one. Expect comments; expect some of
them to be wrong. Say so when they are — a reviewer that is not argued with is not being
used properly.
