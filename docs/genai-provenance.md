# Generative AI provenance

This file records where generative AI was used in this project, and what a human
contributed alongside it. It exists because that distinction has consequences — for anyone
auditing the code, and for funding bodies whose rules make purely generated work
ineligible.

It is kept up to date as work happens. **It cannot be reconstructed afterwards**, which is
the whole reason it was started before the work it covers.

## Why a file, and not commit trailers

The common convention is to name the model as a co-author in each commit. This project does
not do that, deliberately: commit authorship records who takes responsibility for a change,
and that is always a person. A tool that helped produce it is not an author in that sense,
and putting it there blurs a line worth keeping sharp.

The equivalent information lives here instead: versioned, in the repository, auditable
against the git history by date. Anyone wanting per-change granularity can cross-reference
a dated entry below with `git log` for the same period.

## Baseline: what already existed

**Everything in this repository up to and including 2026-08-30 predates any funded work.**
That is 110 commits, from `chore: repo init` on 2026-08-24 to the public release on
2026-08-30, published under AGPL-3.0 at github.com/matteopratesi/zilath. The publication
date is externally verifiable and fixes the boundary: no work below that line is claimed as
funded output.

How the baseline was produced, stated plainly:

- **The code was written in sessions with a large language model**, with the maintainer
  directing, reviewing, correcting and accepting each change. It is not the product of a
  prompt: it is the product of a sequence of decisions, many of which reversed what the
  model had proposed.
- **The design decisions are the maintainer's**, and several are documented as such because
  they are the reason the library behaves the way it does: verify and discard, never fail
  open, strip `cnf` and `status` from returned claims, a receipt instead of a document,
  a substitutable wallet profile.
- **The specification work is human**: which parts of IT-Wallet and OpenID4VP apply, where
  the two disagree (`docs/note-divergenze.md`), which version to target and why
  (`docs/spec-version.md`).
- **Two internal security reviews** were conducted with model assistance and their findings
  fixed; both are described in `SECURITY.md`, including the fact that neither was
  independent.

Nothing about this is hidden, and it should not be: a reviewer who reads the code deserves
to know how it came to exist.

## How entries are recorded from here on

One entry per unit of work that produces a deliverable — a feature, a document, a
migration — not one per commit. Per-commit granularity is unsustainable and would produce a
log nobody reads, which serves nobody.

Each entry states:

| field | meaning |
|---|---|
| **Date** | or date range, cross-referenceable with `git log` |
| **What** | the deliverable, and the commits or files it covers |
| **Model** | name and version of the model used; `none` where no model was involved; `<name>, version not recorded` only for retrospective entries, where naming a version would be a guess. Named at all because funding-body policy requires provenance to state which model was used *including version* — the product name is an accountability record, not an endorsement |
| **Assistance** | what the model actually did — drafting, refactoring, test generation, review, translation |
| **Human contribution** | the decisions, corrections and domain knowledge that were not generated: this is the field that matters, and it is not a formality |
| **Verification** | how the result was checked — tests, review, conformance run, external audit |

An entry with an empty *Human contribution* field is a warning sign about the work, not
about the paperwork.

**On the level of detail.** Funding-body policy asks for the prompts and resulting output
*"or a summary thereof"*, and accepts a general description where the assistance concerned
tests or documentation rather than code. The entries here are that summary. A verbatim
transcript of every interaction would be neither maintainable nor readable, and a register
nobody maintains proves nothing; what an auditor needs is which model, what it did, and
what a person decided instead — which is what each entry states. Raw transcripts for a
specific contribution can be produced on request while the sessions remain available.

## Register

<!--
Template — copy and fill:

### YYYY-MM-DD — <deliverable>

- **What**: <files, modules or commits>
- **Model**: <name and version, or "none">
- **Assistance**: <what it did>
- **Human contribution**: <decisions, corrections, domain knowledge>
- **Verification**: <tests, review, audit>
-->

### 2026-08-24 → 2026-08-30 — Baseline, before any funded work

- **What**: the whole repository at the point of public release — `verifier-core`,
  `verifier-openid4vp`, `verifier-trust-itwallet`, `verifier-spring-boot-starter`,
  `demo-checkout`, `gate-check`, documentation. 110 commits.
- **Model**: Anthropic Claude, version not recorded — several versions over the seven days,
  none logged at the time. This entry is retrospective, and that gap is the reason the
  register now exists: entries from here on name the version at the time of the work.
- **Assistance**: drafting of implementation code and tests, documentation, and two
  internal security reviews.
- **Human contribution**: the entire design — what the library does and refuses to do, the
  privacy constraints that shape the API, the choice of specification version and profile
  seam, the reading of IT-Wallet and OpenID4VP against each other; review and acceptance of
  every change, including the ones rejected or reversed.
- **Verification**: 171 tests, `clean build` green; PagoPA conformance tool completing the
  cross-device flow end to end; automated review on every pull request; two internal
  security reviews with all findings fixed, and no independent external review to date.
- **Funding status**: **pre-existing.** Not claimed as output of any funded work.

<!-- New entries go below, newest last. -->

Model attribution for the three entries that follow, covering 2026-08-31 and 2026-09-01
up to the release — later entries carry their own: three versions were in use across those
two days —
**Anthropic Claude Fable 5, Opus 5 and Opus 4.8** — often alternating within a single
session. Which one produced a given commit was not recorded at the time and is not
reconstructed here; naming the three is accurate, apportioning them would not be.

### 2026-08-31 — This register

- **What**: `docs/genai-provenance.md` and the pointer to it in `README.md`
  (`c9049c1`..`d0bcab5`, PR #28).
- **Model**: Anthropic Claude — Fable 5, Opus 5, Opus 4.8.
- **Assistance**: drafting the document and its schema.
- **Human contribution**: the decision to start a register before the funded work rather
  than reconstruct one after it. The refusal to use commit co-author trailers — commit
  authorship records who takes responsibility, and that is a person. The instruction to name
  the model only where policy requires it and not otherwise. The judgement on detail: a
  summary, not a transcript, checked against what the funding body actually asks for rather
  than against a worst-case reading of it.
- **Verification**: no code. Automated review on the pull request.
- **Funding status**: pre-existing. Written before the call opened on 2026-09-03.

### 2026-08-31 → 2026-09-01 — Making the demo runnable by somebody else

- **What**: `scripts/run-demo-wallet.sh` rewritten; `README.md` demo section (the Node
  22.13 requirement, and what the happy flow does); the configuration error messages in
  `ConformanceDemoApp.kt` with `ConfigurationMessagesTest` (`e121da1`, `e99b3d7`, PR #29;
  `cbaffc9`, PR #31).
- **Model**: Anthropic Claude — Fable 5, Opus 5, Opus 4.8.
- **Assistance**: diagnosing the script, rewriting it, generating the tests.
- **Human contribution**: **the defect was found by the maintainer running the demo**, not
  by the model, and twice over — first the script that hung at step 4, then the startup
  error naming a Spring property nobody sets. Both had been shipped as working. The general
  rule drawn from the two, and applied to the second: a message must name what the reader
  actually sets, not what the program happens to read.
- **Verification**: the demo run by hand end to end; six tests added for the configuration
  messages, and the invariant mutation-checked in both directions — each guard removed and
  the tests watched to fail before it was put back. Automated review on the pull requests
  caught two further inaccuracies in the same messages, both fixed.
- **Funding status**: pre-existing.

### 2026-09-01 — gate-check: extended, then removed

- **What**: first the ticket reference on the gate receipt, with validation of what gets
  stored (`a9cfd44`, `21a3b4d`, PR #30); then the removal of the whole module and its
  traces across six documents (`f8a452f`, PR #32).
- **Model**: Anthropic Claude — Fable 5, Opus 5, Opus 4.8.
- **Assistance**: implementing the reference field; later, surveying every reference to the
  module and rewriting the documents around its absence.
- **Human contribution**: the question that started the first half — *there has to be a
  ticket somewhere, otherwise what is the check for?* — and the judgement that ended the
  second: the tool adds work at the box office without buying anything, in time or in data
  protection, so nobody would adopt it. The model had built the module and then extended
  it; it did not question it until asked to.
- **Verification**: `clean build` green; the removal took 15 tests with it, all the
  module's own.
- **Funding status**: pre-existing.

> Part of the work in the last entry was thrown away. It is recorded because it happened: a
> register that keeps only what survived describes a process nobody actually followed, and
> would be worth less to a reader trying to judge how this project is built.

### 2026-09-02 — Third internal review of the cryptography and trust chain

- **What**: every `main` source of the four library modules read in full (3,466 lines, none
  changed since the second review), two suspected findings tested against the running library,
  fixes with tests on branch `security/review-3`; `SECURITY.md`, `CHANGELOG.md` and
  `docs/privacy-by-design.md` updated. The working notes are the maintainer's files and are not
  published.
- **Model**: Anthropic Claude Fable 5.1 — requested the day that version became available.
- **Assistance**: the reading, the adversarial reasoning, the two probes, the fixes and their
  tests, and the mutation checks showing each test fails against the previous code.
- **Human contribution**: the request itself, deliberately a third pass over unchanged code;
  the earlier decision that `detail` must never carry a claim value — the guarantee this review
  found resting on a dependency's accident rather than on the code; and acceptance of the
  fixes, including the one that removes `iat` and `exp` from what integrators receive, which
  is a behaviour change.
- **Verification**: one suspected finding — disclosure content leaking into `detail` — was
  tested and **found not to occur today**; it is recorded as hardening, not as a vulnerability.
  The IP-literal bypass was reproduced against `InetAddress` before being reported. Three
  mutation checks; `clean build` green with the new tests.
- **Funding status**: pre-existing.

### 2026-09-01 → 2026-09-02 — First publication to Maven Central (0.2.0), then 0.3.0

- **What**: cutting `0.2.0`, verifying the bundle and publishing it under `dev.zilath`; two
  fixes found by inspecting the bundle after Central had validated it and before publishing
  (`META-INF/LICENSE` absent from every jar, `Automatic-Module-Name` absent from every
  manifest), published on 2026-09-01; then `0.3.0` carrying the third review's fixes,
  published on 2026-09-02. Pull requests #34 and #36.
- **Model**: Anthropic Claude Opus 5 for the release work, Fable 5.1 for the review whose
  fixes `0.3.0` ships.
- **Assistance**: the release preparation, the verification of signatures and checksums
  against the artifacts as downloaded from Central, and the scan of the jars.
- **Human contribution**: the decision to publish at all and when; the instruction to look
  inside the bundle before the irreversible step — *"vuoi fare un giro sul codice prima che
  sia troppo tardi?"* — which is what caught the missing licence, in a project whose entire
  commercial model rests on the copyleft; and the release-numbering decision recorded here:
  `0.3.0` rather than `0.2.1`, because removing claims from `Verified.claims` breaks callers
  and this project promises that only minor versions may do that.
- **Verification**: the four modules downloaded back from `repo1.maven.org` after publication
  and checked byte-for-byte against the locally built jars (sha256 identical), signatures
  verified against the published public key, `META-INF/LICENSE` confirmed present in all
  twelve artifacts. `clean build` green, 174 tests.
- **Funding status**: pre-existing.

