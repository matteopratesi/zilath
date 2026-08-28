# Conformance run — 2026-08-24

- Tool: `@pagopa/it-wallet-conformance-tool` **1.2.1**, `test:presentation`, wallet version **V1_4**.
- Target: `demo-checkout` app (this repo) on `http://localhost:8080`, `x509_hash` client id
  scheme with a self-signed certificate, `FederationTrustEvaluator` bootstrapped (TOFU) against
  the tool's local Trust Anchor.
- Result: **33 passed, 36 failed, 22 skipped** (of 91). Full output in
  [presentation-run.log](presentation-run.log).
- **The cross-device happy flow completes end to end**: the tool logs
  `Presentation flow completed successfully` — signed JAR accepted, encrypted
  `direct_post.jwt` response decrypted, mock PID validated through the OpenID Federation
  trust chain, claims disclosed.
- Every failure belongs to one of the gap families listed in
  [../../note-divergenze.md](../../note-divergenze.md): same-device flow (out of v0 scope),
  RP federation onboarding (entity configuration endpoint), or test preconditions on those.

## How to reproduce

1. Generate the RP certificate: `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout rp-key.pem -out rp-cert.pem -days 30 -nodes -subj "/CN=localhost"` then `cat rp-cert.pem rp-key.pem > rp-combined.pem`.
2. Start the app:
   `ZILATH_TRUST_ANCHOR_ID=https://localhost:3001 ZILATH_TRUST_ANCHOR_TOFU=true ZILATH_INSECURE_TLS=true ZILATH_PID_VCT=urn:eudi:pid:it:1 ZILATH_RP_PEM_PATH=<path>/rp-combined.pem ./gradlew :demo-checkout:bootRun`
3. Run the tool (Node >= 22):
   `npx @pagopa/it-wallet-conformance-tool@1.2.1 test:presentation --presentation-authorize-script <script printing the authorizeUrl from GET /conformance/start> --wallet-version V1_4 --unsafe-tls`
