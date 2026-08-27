# varco-verifier

[![build](https://github.com/matteopratesi/varco-verifier/actions/workflows/build.yml/badge.svg)](https://github.com/matteopratesi/varco-verifier/actions/workflows/build.yml)

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

> Working name. Status: pre-alpha — the cross-device flow completes end to end against
> the official PagoPA conformance tool (see [docs/conformance](docs/conformance/)), and
> the API is not frozen yet.
> Target spec: IT-Wallet v1.4.6 — see [docs/spec-version.md](docs/spec-version.md).

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
wallet (the PagoPA conformance tool acts as the wallet — Node >= 22 required).

1. Generate a self-signed RP certificate (the wallet requires the `x509_hash` scheme):

   ```sh
   mkdir -p demo-keys && cd demo-keys && \
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
     -keyout rp-key.pem -out rp-cert.pem -days 30 -nodes -subj "/CN=localhost" && \
   cat rp-cert.pem rp-key.pem > rp-combined.pem && cd ..
   ```

2. Start the app (trust is bootstrapped against the tool's local anchor):

   ```sh
   VARCO_TRUST_ANCHOR_ID=https://localhost:3001 VARCO_TRUST_ANCHOR_TOFU=true \
   VARCO_INSECURE_TLS=true VARCO_PID_VCT=urn:eudi:pid:it:1 \
   VARCO_RP_PEM_PATH=$PWD/demo-keys/rp-combined.pem \
   ./gradlew :demo-checkout:bootRun
   ```

3. Open <http://localhost:8080/demo>, click "Ho diritto al biglietto accompagnatore" and
   copy the transaction id shown on the QR page.
4. Let the test wallet present the PID:

   ```sh
   ./scripts/run-demo-wallet.sh <transactionId>
   ```

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
VARCO_TRUST_ANCHOR_ID=https://anchor.ced-sim.varco.invalid \
VARCO_TRUST_ANCHOR_JWKS_PATH=$PWD/demo-keys/ced-sim/anchor-jwks.json \
VARCO_DEMO_CREDENTIAL_MODE=ced-sim ./gradlew :demo-checkout:bootRun
# then, with the transaction id from the QR page:
./scripts/run-ced-wallet.sh <transactionId>
```

For the full conformance run against this RP, see [docs/conformance](docs/conformance/).

## Gate check — the tool that helps today

`gate-check` is a tiny self-hosted web app for the venue's entrance, usable **now**,
before wallet verification opens to private relying parties: the operator follows a
guided flow (person shows the European Disability Card, operator verifies its QR on the
INPS service — exactly what the State expects), and the tool records **only a signed
outcome receipt**: venue, entitlement, outcome, operator, timestamp. Never a name, a
document, a photo, a percentage. No free-text field exists, on purpose.

```sh
VARCO_GATE_VENUE="Teatro di Prova" ./gradlew :gate-check:bootRun
# then open http://localhost:8081/gate
```

Receipts (JWS, `varco-gate-receipt+jwt`) and the venue signing key live under
`VARCO_GATE_DATA_DIR` (default `./gate-data`, created owner-only; forged lines in the
receipts file are excluded on load). Trust model: the app binds to `127.0.0.1` by
default; expose it on the venue LAN explicitly (`VARCO_GATE_BIND=0.0.0.0`) and only
behind the venue's own network — whoever can reach the pages can record receipts, so
the network is the trust boundary (there is no user login by design: it is a
single-venue, door-side tool). The `method` claim is the migration seam:
today `manual-inps-qr`; when private relying parties can receive wallet presentations,
the same receipt is issued as `wallet-openid4vp` by the library flow — the venue's
process and records do not change.

## License

AGPL-3.0 — free to use in open-source software. For embedding in closed-source commercial
products, a commercial license is available: contact the author.
