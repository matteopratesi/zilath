# Zilath

[![build](https://github.com/matteopratesi/zilath/actions/workflows/build.yml/badge.svg)](https://github.com/matteopratesi/zilath/actions/workflows/build.yml)

A Kotlin/JVM library that lets any JVM application act as an **OpenID4VP relying party**
for European digital identity wallets: request a credential from the user's wallet
(cross-device QR or same-device link), receive and cryptographically verify it
(SD-JWT VC), and get back a minimal yes/no outcome — **without ever storing the
credential**. What a verification leaves behind is the transaction's own bookkeeping
(nonce, outcome, expiry) and the signed receipt: never the presented document, never a
claim value.

Wallet behavior is a pluggable **profile**: the Italian **IT-Wallet** profile is the
default and the most complete (signed JAR, encrypted `direct_post.jwt`, OpenID
Federation trust), and an **ARF baseline** profile targets EUDI wallets in any member
state. The European Disability Card — the launch use case — is itself an EU instrument
(Directive (EU) 2024/2841, mutual recognition from June 2028).

Born for accessibility rights: letting a person with a disability prove an entitlement
(companion ticket, priority access) online without ever sending health documents to anyone.

> *Zilath* was the chief magistrate of an Etruscan city: the office that ascertained a
> claim and made it binding. That is the whole job of this library — it verifies what a
> public authority has already attested. It never issues a credential, and it never
> decides who qualifies.
>
> Status: pre-alpha — the cross-device flow completes end to end against the official
> PagoPA conformance tool (see [docs/conformance](docs/conformance/)), and the API is
> not frozen yet.
> Target spec: IT-Wallet v1.4.6 — see [docs/spec-version.md](docs/spec-version.md).
>
> What this library does with the data it touches, what it keeps and what it cannot
> promise: [docs/privacy-by-design.md](docs/privacy-by-design.md).

## Modules

| Module | Purpose |
|---|---|
| `verifier-core` | Pure JVM credential verification (SD-JWT VC). No framework, no network I/O. |
| `verifier-openid4vp` | Relying-party flow: transactions, request JWT, `direct_post`, replay protection. |
| `verifier-trust-itwallet` | OpenID Federation trust chain evaluation, `metadata_policy`. |
| `verifier-spring-boot-starter` | Spring Boot auto-configuration and endpoints. |
| `demo-checkout` | Demo app: fake event checkout unlocking a companion ticket. |
| `gate-check` | Self-hosted gate tool for venues: guided CED check, signed outcome-only receipts. |

## Build

Requires JDK 21 (a Gradle toolchain will pick it up).

```sh
./gradlew build
```

## Try the demo

A fake event checkout that unlocks a companion ticket by presenting the test PID from a
wallet, with the PagoPA conformance tool acting as the wallet.

**Node >= 22.13 is required** (or any Node 23+) — the tool imports `node:sqlite`, which
became available unflagged in 22.13, and on a runtime without it the tool hangs rather than
failing cleanly. With `nvm`: `source ~/.nvm/nvm.sh && nvm use 22`, then run the steps below
from that same shell. The script checks this for you before doing anything else.

1. Generate a self-signed RP certificate (the wallet requires the `x509_hash` scheme):

   ```sh
   mkdir -p demo-keys && cd demo-keys && \
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
     -keyout rp-key.pem -out rp-cert.pem -days 30 -nodes -subj "/CN=localhost" && \
   cat rp-cert.pem rp-key.pem > rp-combined.pem && cd ..
   ```

2. Start the app (trust is bootstrapped against the tool's local anchor):

   ```sh
   ZILATH_TRUST_ANCHOR_ID=https://localhost:3001 ZILATH_TRUST_ANCHOR_TOFU=true \
   ZILATH_INSECURE_TLS=true ZILATH_PID_VCT=urn:eudi:pid:it:1 \
   ZILATH_RP_PEM_PATH=$PWD/demo-keys/rp-combined.pem \
   ./gradlew :demo-checkout:bootRun
   ```

3. Open <http://localhost:8080/demo>, click "Ho diritto al biglietto accompagnatore" and
   copy the transaction id shown on the QR page.
4. Let the test wallet present the PID (transactions live 5 minutes, so use a fresh id):

   ```sh
   ./scripts/run-demo-wallet.sh <transactionId>
   ```

   The script runs only the conformance tool's happy-flow tests, and there is a reason:
   the other suites deliberately post authorization *error* responses, and an OpenID4VP
   transaction is single-use — the first error response consumes its nonce, so everything
   after it correctly gets `REPLAY` and the happy flow finds the request endpoint already
   closed. One transaction cannot serve the whole suite. For the full run, see
   [docs/conformance](docs/conformance/).

   Some conformance assertions fail even in the happy flow: they are the known gaps in
   [docs/note-divergenze.md](docs/note-divergenze.md), not regressions. What decides
   whether the presentation went through is the transaction status, which the script
   reports at the end.

5. The page turns into a nominative companion ticket; the "ricevuta di verifica" link is
   the signed receipt a venue would keep — outcome and timestamp, never a document.

### Simulated CED mode

The same checkout can ask for a **simulated European Disability Card** instead of the PID —
the ticket then unlocks on the *entitlement*, not on identity. The real CED has been a
production IT-Wallet credential on app IO since December 2024: configuration
`dc_sd_jwt_EuropeanDisabilityCard`, whose issuer metadata advertises
`vct: https://ta.wallet.ipzs.it/vct/v1.0.0/europeandisabilitycard` (verified against the
production entity statement on 2026-08-25; the same URL serves the credential type metadata —
newer issuer versions may adopt the spec's `urn:eudi:<type>:it:1` vct convention instead).
What does not exist yet is production verification by private relying parties. The simulation therefore mirrors the real
claim names (`given_name`, `family_name`, `constant_attendance_allowance`, `expiry_date`) under
an openly fake vct and federation — it never impersonates the real issuer — and discloses only
that minimized subset (never portrait, birth date or document number). Note the semantic limit
of the real claim: `constant_attendance_allowance` covers the attendance allowance, not every
card printed with the companion "A".

```sh
./scripts/run-ced-wallet.sh init
ZILATH_TRUST_ANCHOR_ID=https://anchor.ced-sim.zilath.invalid \
ZILATH_TRUST_ANCHOR_JWKS_PATH=$PWD/demo-keys/ced-sim/anchor-jwks.json \
ZILATH_DEMO_CREDENTIAL_MODE=ced-sim ./gradlew :demo-checkout:bootRun
# then, with the transaction id from the QR page:
./scripts/run-ced-wallet.sh <transactionId>
```

For the full conformance run against this RP, see [docs/conformance](docs/conformance/).

## Gate check — the tool that helps today

`gate-check` is a tiny self-hosted web app for the venue's entrance, usable **now**,
before wallet verification opens to private relying parties: the operator follows a
guided flow (person shows the European Disability Card, operator verifies its QR on the
INPS service — exactly what the State expects), and the tool records **only a signed
outcome receipt**: venue, entitlement, outcome, operator, timestamp, and the venue's own
reference for the ticket or order the check authorised. Never a name, a document, a photo,
a percentage. No free-text field exists, on purpose.

The ticket reference is what makes the receipt a *replacement* for the document rather than
a ritual: without it a receipt proves that a check happened but not what it allowed, which
is exactly what a venue needs when reconciling takings months later. It is meant to be a
commercial identifier — an order number, a seat. The tool rejects the shapes of personal
data it can recognise (an email address, an Italian tax code), but it cannot tell a booking
code from a surname: **keeping the field free of personal data is an instruction to the
operator, not a guarantee the software can make.** The form says so where it is typed.

```sh
ZILATH_GATE_VENUE="Teatro di Prova" ./gradlew :gate-check:bootRun
# then open http://localhost:8081/gate
```

Receipts (JWS, `zilath-gate-receipt+jwt`) and the venue signing key live under
`ZILATH_GATE_DATA_DIR` (default `./gate-data`, created owner-only; forged lines in the
receipts file are excluded on load). Trust model: the app binds to `127.0.0.1` by
default; expose it on the venue LAN explicitly (`ZILATH_GATE_BIND=0.0.0.0`) and only
behind the venue's own network — whoever can reach the pages can record receipts, so
the network is the trust boundary (there is no user login by design: it is a
single-venue, door-side tool). The `method` claim is the migration seam:
today `manual-inps-qr`; when private relying parties can receive wallet presentations,
the same receipt is issued as `wallet-openid4vp` by the library flow — the venue's
process and records do not change.

## Contributing

Issues and pull requests are welcome — read [CONTRIBUTING.md](CONTRIBUTING.md) first, in
particular the red lines the project will not cross. Contributions are covered by the
[Contributor License Agreement](CLA.md), accepted by signing off your commits
(`git commit -s`).

## How this was built

This library was written with the assistance of a large language model, under human
direction and review. Where that assistance was used, and what was decided rather than
generated, is recorded in [docs/genai-provenance.md](docs/genai-provenance.md) — kept
current as work happens, because it cannot be reconstructed afterwards.

## Security

Found a vulnerability? **Do not open a public issue** — see [SECURITY.md](SECURITY.md) for
the private reporting channel, the boundaries this library deliberately does not defend,
and the current state of cryptographic review.

## License

AGPL-3.0, with a commercial licence available as an alternative. What separates the two is
not whether you make money from it: it is **whether the software that incorporates the
library is open or closed**.

The AGPL does not forbid commercial use. It is, however, strong copyleft, and incorporating
the library into an application is generally understood to produce a work based on it:
conveying that application means giving recipients its Corresponding Source under the same
licence, and — this is what separates the AGPL from the GPL — letting users interact with a
modified work over a network means offering them that source too, even though no copy was
ever distributed. So:

- **open software** — use it freely and at no cost, including inside a paid service;
- **closed software** — the AGPL terms cannot be met, and the commercial licence applies.

The second case covers proprietary ticketing and venue systems, which is the setting this
library was written for. The commercial licence is the project's only intended source of
revenue: contact the author.

Where that cost falls is a property of the model rather than an accident of it — on
organisations that choose to keep their own software closed. **The person being verified
never pays and is never metered.** Not because the price was set that way, but because it
is a stated constraint of the project: section 4 of the [CLA](CLA.md). The project may not
be transferred to anyone who has not accepted that section in writing — and a transfer made
without it does not carry the relicensing right along with it.

The commercial licence only ever exists *alongside* the open one. Every release stays
available under the AGPL-3.0, or another licence approved by the Open Source Initiative
granting at least the same freedoms, and no feature is withheld from it.
