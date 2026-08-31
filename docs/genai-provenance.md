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
| **Model** | name and version of the model used, or *none*. Named here because funding-body policy requires provenance to state which model was used *including version* — the product name is an accountability record, not an endorsement |
| **Assistance** | what the model actually did — drafting, refactoring, test generation, review, translation |
| **Human contribution** | the decisions, corrections and domain knowledge that were not generated: this is the field that matters, and it is not a formality |
| **Verification** | how the result was checked — tests, review, conformance run, external audit |

An entry with an empty *Human contribution* field is a warning sign about the work, not
about the paperwork.

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
- **Model**: Anthropic Claude — several versions over the seven days, not individually
  logged at the time. This entry is retrospective, and its precision is the reason the
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
