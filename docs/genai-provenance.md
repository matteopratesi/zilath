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
against the git history by date.

**Since 2026-09-29 it is also recorded per commit, in git notes.** Each commit made with
model assistance carries a note under `refs/notes/genai`: the model, a summary of the
prompts, what the model did, what a person decided, and how the result was checked. A note is
attached to a commit without being part of it, so the commit's message and authorship stay
the person's. This file keeps one entry per pull request, which says the same for the change
as a whole.

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

**Until 2026-09-28**, one entry per unit of work that produces a deliverable — a feature, a
document, a migration — and not one per commit.

**From 2026-09-29**, two levels:

- **a git note on each commit** made with model assistance, under `refs/notes/genai`, with the
  fields *Model*, *Prompts (summary)*, *Assistance*, *Human contribution* and *Verification*;
- **one entry here per pull request**, with the fields below.

The change follows the funding body's published guidance, which expects disclosure per commit
for generated code and accepts equivalent methods. Notes give that granularity without making
a model the author of a commit.

To read the notes, which the GitHub web interface does not show:

```sh
git fetch origin refs/notes/genai:refs/notes/genai
git log --notes=genai
git notes --ref=genai show <commit>
```

Pull requests are merged with a merge commit, so the commits that carry the notes reach
`main` unchanged. Whoever rebases or amends a commit that has a note should first run
`git config notes.rewriteRef refs/notes/genai`, so that the note follows the rewritten commit.

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
  Reconstructed on 2026-09-29 from the session logs: Claude Fable 5 and Claude Opus 5, and
  Claude Opus 4.8 for a few minutes on 2026-08-30.
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
up to the release — later entries carry their own: **Anthropic Claude Opus 5**. These entries
first named Fable 5, Opus 5 and Opus 4.8, as three versions in use across those two days with
no record of which produced what. The session logs, read on 2026-09-29, show Opus 5 alone on
both days; Fable 5 and Opus 4.8 were in use on 2026-08-30, under the entry above.

### 2026-08-31 — This register

- **What**: `docs/genai-provenance.md` and the pointer to it in `README.md`
  (`c9049c1`..`d0bcab5`, PR #28).
- **Model**: Anthropic Claude Opus 5 (corrected on 2026-09-29; see the note above).
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
- **Model**: Anthropic Claude Opus 5 (corrected on 2026-09-29; see the note above).
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
- **Model**: Anthropic Claude Opus 5 (corrected on 2026-09-29; see the note above).
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

### 2026-09-04 → 2026-09-24 — Fourth internal review

- **What**: an adversarial review of 0.3.0 (commit `4a90ef0`): nineteen lenses, each with its
  own mandate and free to execute probes, every finding put to an adversarial judge, and the
  critical and high ones reproduced by an independent probe. 83 findings confirmed — 64 on an
  execution with its log, 19 on reasoning — and 4 refuted. For the first time the production
  IT-Wallet federation documents were fetched, read-only, and replayed unmodified. The report is
  the maintainer's working notes and is not published.
- **Model**: Anthropic Claude Fable 5.1 (search, deduplication and the first seven chunks of
  verification), Claude Opus 5.5 (the remaining verification chunks, the completeness critic and
  the synthesis), and Claude Opus 4.8 for part of the work of two reviewer sub-agents, on
  2026-09-04 and 2026-09-05, which had started on Fable 5.1 (added on 2026-09-29 from the
  session logs).
- **Assistance**: the whole review: the probes, the judgements, the reproductions, the
  synthesis.
- **Human contribution**: commissioning a fourth review of code already reviewed three times,
  and against real documents rather than fixtures; the decision to finish the run with the
  second model once one chunk, judged again blind with the same prompt, gave the same verdicts
  and severities four times out of four.
- **Verification**: every confirmed finding either rests on an execution with its log or has
  judge and reproducer agreeing; the report's opening was re-read against the data before it was
  closed, which removed three sentences the data did not support.
- **Funding status**: pre-existing.

### 2026-09-25 → 2026-09-27 — The fourth review's fixes

- **What**: the fixes of the review's findings in three stacked pull requests — #39 shared
  rules, `verifier-core` and the build; #40 `verifier-trust-itwallet`; #41 `verifier-openid4vp`,
  the Spring starter, the demo and the documentation — with `CHANGELOG.md`. Among them: a card
  shaped as IT-Wallet 1.4.6 writes it now verifies against the production federation's
  documents, re-signed with substitute keys under their real `kid`s; the demo's transactions are
  bound to the browser that started them; the receipt records the caller's verdict; the Spring
  Security guide is tested; the relying party publishes its trust marks; the documentation says
  what the code does.
- **Model**: Anthropic Claude Opus 5.5, as a coordinator and as sub-agents working in parallel,
  each on one module, or on the documentation, in its own worktree.
- **Assistance**: the fixes and their tests, the mutation checks, the merges between the stacked
  branches, the coordinator's re-run of each commit's tests and of at least one of its mutations
  in a separate checkout, a read-only pre-review of #41 by a sub-agent ahead of the automated
  review, the fixes of the automated review's findings, and the KDoc of every non-private
  function the review touched that had none.
- **Human contribution**: the scope — every finding, LOW and INFO included; the rule that work
  runs in parallel only where it cannot conflict; the decision, midway, to stop at the issues
  already started and put the demo and the documentation on hold, and the later one to close
  every remaining finding before the merge; one pull request per area, to stay under the
  automated reviewer's file limit, each merged only once that review found nothing more.
- **Verification**: every behaviour fix has a test that fails against the previous code; the
  trust decision on the production documents, untouched, has a test of its own; `clean build`
  green on each pull request, with dependency verification, CI green, and the automated review
  repeated until the head drew no actionable comment.
- **Funding status**: pre-existing.

### 2026-09-27 — The library's own HTTP fetchers

- **What**: `HttpDocumentFetcher` in `verifier-core` and `HttpFederationFetcher` in
  `verifier-trust-itwallet`, over the JDK's HTTP client: a host is fetched from only when every
  address it resolves to is globally routable, no redirect is followed, and time and response
  size are bounded. The demo moved onto them; `SECURITY.md`, the README, privacy-by-design and
  `CHANGELOG.md` say what they hold and what they leave open. Prompted by a concern the automated
  review kept in its security architecture review of #40. Pull request #45.
- **Model**: Anthropic Claude Opus 5.5.
- **Assistance**: the two classes and the address classification, their tests, one mutation
  check per protection (eighteen), the documentation changes, the issue's text, and the fixes
  of the automated review's findings: the name lookup inside the fetch's deadline, with a bound
  on lookups at once, and the demo's trust-all TLS held to addresses that are loopback too.
- **Human contribution**: the decision to ship a fetcher in the library instead of leaving the
  boundary documented only, and the choice of the JDK's client with no new dependency, accepting
  the DNS rebinding window that a dependency could have closed.
- **Verification**: every protection has a test that fails once that protection is removed;
  `clean build` green, with dependency verification; the automated review repeated on #45,
  whose last two findings, both in code #46 replaces, are fixed there. Merged with #46 on
  2026-09-28.
- **Funding status**: pre-existing.

### 2026-09-27 — Connecting only to the checked addresses

- **What**: `HttpDocumentFetcher` moved off the JDK's HTTP client onto a minimal HTTP/1.1
  exchange over the JDK's sockets and TLS, so that the connection goes to an address the check
  approved and to no other: the name is resolved once, and DNS rebinding has nothing to change.
  TLS keeps the name for SNI and for the certificate's verification. The reader holds a response
  to bounded lines, head and body, and refuses what it would have to guess at. `allowLoopback`
  became `destinations`, whose `LOOPBACK` keeps the demo's trust-all TLS on this machine by the
  same single lookup. Prompted by the concern the automated review kept, as High, on the
  previous deliverable's pull request. Pull request #46, stacked on #45.
- **Model**: Anthropic Claude Opus 5.5.
- **Assistance**: the exchange and the response reader, their tests — among them a TLS test
  against names no resolver knows, which only a pinned connection can pass — one mutation check
  per protection (twenty-four), the documentation changes, and the fixes of the automated
  review's findings: non-ASCII paths percent-encoded, the request bounded so that writing it
  cannot block, and a socket closed however opening TLS on it fails.
- **Human contribution**: the choice, among three options laid out, of a minimal HTTP/1.1 client
  on the JDK's sockets over a new dependency and over leaving the window documented, accepting
  that the JVM's proxy settings are no longer used.
- **Verification**: every protection has a test that fails once that protection is removed;
  `clean build` green, with dependency verification; the automated review repeated until the
  head drew no actionable comment. Merged after #45 on 2026-09-28.
- **Funding status**: pre-existing.

### 2026-09-28 — Cutting 0.4.0

- **What**: the release pull request for `0.4.0`. The section of `CHANGELOG.md`: its title and
  date, and an opening that says what the release carries — the fourth review's fixes (#39, #40,
  #41) and the library's own HTTP fetchers (#45, #46) — and what `0.3.0` cannot do that `0.4.0`
  does; three of its paragraphs reflowed, no word changed; a note on the Tomcat advisories. The
  version in `build.gradle.kts` and in `docs/releasing.md`'s verify command, and that file's
  table of what is published; the README's version, its migration note from `0.3.0`, and the
  sentences about unreleased code on `main` in the README and `SECURITY.md`, now about `0.4.0`.
  The publication follows `docs/releasing.md` and is recorded once done.
- **Model**: Anthropic Claude Opus 5.5.
- **Assistance**: the opening, with each of its claims checked against the test or the code
  that establishes it: `IpzsProductionChainTest` for the trust decision on the untouched
  production documents, `ProductionCedEndToEndTest` for the card verified end to end and the
  status assertion still refused, and the constructors it calls source-compatible; the
  advisory lookup of `docs/releasing.md` step 2, run on every artifact of the starter's
  runtime classpath, fifty of them, rather than on the four libraries the step names.
- **Human contribution**: the decision to cut the release, numbered `0.4.0`.
- **Verification**: the opening read against the tests and constructors named above; a
  word-level diff showing the reflowed paragraphs unchanged; OSV queried for the fifty
  artifacts: three advisories, all on Tomcat 11.0.24, in features no module uses — checked
  by searching the sources for them.
- **Funding status**: pre-existing.

### 2026-09-28 — Publication of 0.4.0

- **What**: `0.4.0` built from `main` at `0512cca`, the merge of #47, signed, checked, uploaded
  to Maven Central and published; the tag `v0.4.0` on the same commit, signed with the artifact
  key. After it, the next development version, `0.5.0-SNAPSHOT`, and two corrections found on the
  way: the README said the starter brings every module, and its POM does not bring
  `verifier-trust-itwallet`; four KDoc links Dokka could not resolve, two of them there since
  `0.3.0`.
- **Model**: Anthropic Claude Opus 5.5.
- **Assistance**: the release steps given one at a time, and the checks around the irreversible
  one: `docs/releasing.md` step 2 run on `main`; the bundle read beyond what
  `scripts/verify-bundle.sh` checks — every signature verified against the artifact key,
  `META-INF/LICENSE` in all twelve jars, `Automatic-Module-Name` in the four main ones, no key
  material, the POMs' coordinates, licence and dependencies; after publication, every artifact
  downloaded back from Central and compared with the bundle.
- **Human contribution**: the decision to publish that day; every step that needs the signing key
  or the Central token — exporting the key, the upload, the deliberate publication in the Portal,
  the signed tag.
- **Verification**: the twenty artifacts served by `repo1.maven.org` identical, by SHA-256, to the
  twenty of the bundle built here, and their twenty signatures, as downloaded, valid with key
  `6A207A58428BC47BA9AC0029392ABDC140E3041A`; `git tag -v v0.4.0` valid, on `0512cca`.
- **Funding status**: pre-existing.

### 2026-09-29 — setup-gradle 6.3.0 with the open-source cache, and provenance per commit

- **What**: `.github/workflows/build.yml` — `gradle/actions/setup-gradle` from v4.4.3 to v6.3.0
  with `cache-provider: basic`, and the comment on the pinned SHAs, which still named the v4 tags
  of 2026-09-25 after #42 and #44 had moved `checkout` and `setup-java` to v7.0.1 and v6.0.1.
  This file and the README, for the move to notes. The notes on the commits of this pull
  request.
- **Model**: Anthropic Claude Opus 5.5.
- **Assistance**: the review of the three Dependabot pull requests, #42, #43 and #44: each
  proposed SHA checked against its release's tag through the GitHub API, and the release notes
  between the pinned and the proposed versions read for breaking changes. That review found that
  setup-gradle caches, since v6, through a proprietary component by default. Then the workflow
  change, the new recording method and this entry.
- **Human contribution**: not accepting the proprietary component's terms, and using the
  MIT-licensed cache instead; merging #42 and #44 as Dependabot proposed them; recording
  provenance per commit in notes, so that commit authorship stays with a person.
- **Verification**: the workflow's own pin check run locally on the changed file; the workflow
  parsed as YAML; CI on the pull request; `git notes --ref=genai show` on each of its commits.
- **Funding status**: pre-existing.

### 2026-09-29 — The demo checks revocation

- **What**: `demo-checkout` — the example `StatusChecker`, which answered `UNKNOWN`, replaced by
  a `StatusListFetcher` bean on which the starter builds its `OAuthStatusListChecker`, with the
  fetcher next to the demo's federation fetcher; tests in `HttpFetcherTest` and
  `DemoCheckoutSmokeTest`, and the test of the removed checker deleted. `SECURITY.md` and
  `CHANGELOG.md`.
- **Model**: Anthropic Claude Opus 5.5.
- **Assistance**: a rerun of the PagoPA conformance tool 1.2.1 against 0.4.0, and the reading
  of its logs and sources, which found that the tool's PID carries a status list reference the
  demo could only answer `UNKNOWN` to. Then this change, its tests and this entry.
- **Human contribution**: choosing a real status list check over the static `VALID` the demo
  had until 2026-09-26, after being shown both; authorising the diagnostic runs below.
- **Verification**: the demo module's checks; the new fetcher test failing when the fetcher's
  destinations are changed to public only; the tool's presentation suite against the changed
  demo, in a local copy whose trust chain check was disabled because the tool's mocked chain
  does not pass it: the happy flow completed with the PID's status list fetched from the
  tool's issuer, and failed with `STATUS_CHECK_FAILED` when the issuer's name did not resolve.
- **Funding status**: pre-existing.

### 2026-09-29 — Trust marks in a subordinate statement

- **What**: `verifier-trust-itwallet` — `trust_marks` taken out of the claims the chain check
  refuses in a subordinate statement, with its KDoc; a test for a chain whose subordinate
  statement carries trust marks, and the existing test kept on the other four claims.
  `CHANGELOG.md`.
- **Model**: Anthropic Claude Opus 5.5.
- **Assistance**: while checking a report to the PagoPA conformance tool against IT-Wallet
  1.4.6, found that the profile lets a subordinate statement carry trust marks, which the check
  added in 0.4.0 refused. Checked every 1.4.x release, the library's use of trust marks (none
  in a chain) and the subordinate statements of the production trust anchor. Then the change,
  its tests and this entry.
- **Human contribution**: the decision to follow the profile the library targets rather than
  OpenID Federation 1.0 on this point, after weighing the proposal and the conflict between the
  two specifications.
- **Verification**: the module's checks; putting `trust_marks` back in the list fails the new
  test, and taking `authority_hints` out fails the existing one; the conformance tool 1.2.1
  against the change still refuses its mocked chain, for `authority_hints`
  (pagopa/wallet-conformance-test#238); against a local copy of the tool with the change that
  issue proposes, the presentation happy flow completes with no check disabled.
- **Funding status**: pre-existing.

### 2026-09-29 — Model attribution corrected from the session logs

- **What**: this file — the model named for 2026-08-24 → 2026-08-30, for the three entries of
  2026-08-31 and 2026-09-01, and for the fourth internal review, reconstructed from the Claude
  Code session logs of the project, sub-agents included.
- **Model**: Anthropic Claude Opus 5.5.
- **Assistance**: counting, per day, which model produced each logged response in the sessions
  working on the project, and writing the corrections and this entry.
- **Human contribution**: the request to state in the funding proposal only what the logs show,
  and so to correct the register where it said more.
- **Verification**: the per-day counts from the session logs: Opus 5 alone on 2026-08-31 and
  2026-09-01; Fable 5 and Opus 5 from 2026-08-23 to 2026-08-30, with Opus 4.8 on 2026-08-30
  only; Opus 4.8 in two reviewer sub-agents on 2026-09-04 and 2026-09-05, each starting on
  Fable 5.1.
- **Funding status**: pre-existing.

### 2026-10-01 — IT-Wallet 1.4.7: the target, and the algorithms and key sizes it asks for

- **What**: `docs/spec-version.md`, the README, `docs/note-divergenze.md` and
  `docs/privacy-by-design.md` — the target moved to IT-Wallet 1.4.7. `verifier-core` — one list
  of the signature algorithms accepted (ES256, ES384, ES512, PS256, PS384, PS512) for every
  signature the library checks, RSA keys from 3072 bits, and a presentation's algorithms read
  before its issuer's trust is asked. `verifier-trust-itwallet` — the same list on every entity
  statement of a chain, with its own failure message. Tests for each path, the RSA test vectors
  moved to 3072 bits and PS256, and `CHANGELOG.md`.
- **Model**: Anthropic Claude Opus 5.5 (the comparison of the two releases, the review, the
  corrections to the wording and this entry) and Claude Sonnet 5.5 (the code and the tests, as
  a sub-agent working from a written brief).
- **Assistance**: compared 1.4.6 and 1.4.7 in the specification repository, release notes and
  the diff of the sources, against the library's code: the relying party's flow is unchanged,
  and two tests of the signature test plan, ATT-004 (the algorithms a signature may use) and
  ATT-006 (at least 128 bits of security strength), now ask for what the library did not do.
  Then the change, its tests and the documents.
- **Human contribution**: the decision to move the target to 1.4.7 with no transition period,
  since the library has no users yet.
- **Verification**: a clean build of every module, 564 tests; taking the algorithm list out
  fails 13 of the new tests, putting the RSA floor back to 2048 bits fails 7, and moving the
  presentation's algorithm check back after the trust evaluation fails 1; what the documents
  say about 1.4.7, read against the specification's text at both tags.
- **Funding status**: pre-existing.
