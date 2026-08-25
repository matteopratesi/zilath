# varco-verifier

[![build](https://github.com/matteopratesi/varco-verifier/actions/workflows/build.yml/badge.svg)](https://github.com/matteopratesi/varco-verifier/actions/workflows/build.yml)

A Kotlin/JVM library that lets any JVM application act as an **OpenID4VP relying party with
the Italian IT-Wallet profile**: request a credential from the user's wallet (cross-device
QR flow), receive and cryptographically verify it (SD-JWT VC), and get back a minimal
yes/no outcome — **without ever storing anything**.

Born for accessibility rights: letting a person with a disability prove an entitlement
(companion ticket, priority access) online without ever sending health documents to anyone.

> Working name. Status: pre-alpha, milestone M0.1 (project skeleton).
> Target spec: IT-Wallet v1.4.6 — see [docs/spec-version.md](docs/spec-version.md).

## Modules

| Module | Purpose |
|---|---|
| `verifier-core` | Pure JVM credential verification (SD-JWT VC). No framework, no network I/O. |
| `verifier-openid4vp` | Relying-party flow: transactions, request JWT, `direct_post`, replay protection. |
| `verifier-trust-itwallet` | OpenID Federation trust chain evaluation, IT-Wallet profile. |
| `verifier-spring-boot-starter` | Spring Boot auto-configuration and endpoints. |
| `demo-checkout` | Demo app: fake event checkout unlocking a companion ticket. |

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

## License

AGPL-3.0 — free to use in open-source software. For embedding in closed-source commercial
products, a commercial license is available: contact the author.
