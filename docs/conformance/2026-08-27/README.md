# Conformance run — 2026-08-27

Tool: `@pagopa/it-wallet-conformance-tool` **1.2.1**, `test:presentation`, wallet **V1_4**.

| run | passed | failed | skipped |
|---|---|---|---|
| 2026-08-24 (M0) | 33 | 36 | 22 |
| this morning, right after the gap PRs | 33 | 36 | 22 |
| **after wiring the harness** | **67** | **23** | **1** |

The middle row is the point: merging the same-device flow, the entity configuration and
`metadata_policy` changed nothing on its own, because **the harness never reached them**.
Reading the tool's own test sources ([presentation-run-after.log](presentation-run-after.log)
is the run these notes describe) showed exactly why:

1. The tool derives the metadata base from `client_id`; with `x509_hash:<hash>` that is not
   an HTTPS URL, so it **skipped the metadata step entirely** — and the whole
   `authorization-request` spec file (21 tests) aborted in `beforeAll` and was never scored.
2. Its `RedirectUriDefaultStep` **always** expects the `direct_post.jwt` acknowledgement to
   carry `redirect_uri` with a `response_code` — it behaves like a same-device wallet even
   in a cross-device run.

## What was changed (and why each is correct beyond the tool)

- **Conformance transactions run in `SAME_DEVICE` mode.** The tool POSTs the response and
  then expects to be handed a redirect back: that *is* the same-device flow, whatever the
  QR suggests. No spec bending — we simply stopped mislabelling the transaction.
- **`client_id` scheme is configurable**; the run uses `openid_federation:<entity id>`, the
  JAR carries the RP's own entity configuration in its `trust_chain` header, and the tool
  resolves us offline. Both prefixes stay supported.
- **The published JWKS matches the request object's**: the encryption key is advertised
  with its `alg` and `use: "enc"`, in the entity configuration as well, so a wallet that
  resolves us through the federation finds the very key it is asked to encrypt to.
- **Wallet error responses are acknowledged with 200 whatever the session state**
  (OpenID4VP §8.2) — an error grants nothing, and the recorded outcome is never clobbered.
- **The return leg is a real session URL**: `<callback>/<transaction id>?response_code=…`,
  so an unknown session (401) is told apart from an invalid or spent code (400), and an
  `error` in the query never consumes the code.
- **An echoed `nonce` in the response payload must match the transaction** (defence in
  depth; the binding that matters stays the one inside the key-binding JWT).

Reproduce it: start the demo with `ZILATH_DEMO_CLIENT_ID_SCHEME=openid-federation` (plus
the environment in [../2026-08-24/README.md](../2026-08-24/README.md)), copy
[config.ini](config.ini) into the directory you run the tool from — the `[presentation]
verifier` key has no CLI flag, which is why it must live in a file — and run:

```sh
npx @pagopa/it-wallet-conformance-tool@1.2.1 test:presentation \
  --presentation-authorize-script <repo>/scripts/conformance-authorize.sh \
  --wallet-version V1_4 --unsafe-tls
```

[`scripts/conformance-authorize.sh`](../../../scripts/conformance-authorize.sh) prints the
authorize URL of a fresh transaction, which is all the tool asks of it.

## The 23 that still fail, honestly

**17 — deliberate refusal (RPR-29/30/31/32/33/34/42/43/44/45/56/57/58/69/70/71/72).**
Every one of these first calls the tool's `fetchRedirectUrl()`, which **re-POSTs the same
JARM** to mint a *fresh* return ticket. Our transactions consume their nonce exactly once,
so the replay is rejected and the test never reaches its own assertion. Satisfying it would
mean handing a fresh bearer return ticket to anyone able to replay a captured response —
the session would go to whoever replays it. The single-use property stays.

**2 — hosting artifact (RPR-01, RPR-84).** Both assert the redirect scheme is `https:` or
`haip:`; the demo runs on `http://localhost:8080`. A TLS-terminated deployment passes.

**2 — a bug in the tool (RPR-105, RPR-106).** It signs the key-binding JWT with
`aud = <raw client_id>` (prefix included) and then asserts `aud` equals the **stripped**
identifier. The two can never match for any spec-compliant prefixed `client_id`
(`openid_federation:` or `x509_hash:`) — only a bare `https://…`, which the IT-Wallet
profile does not allow.

**2 — newly visible, not yet diagnosed (RPR-39, RPR-68).** They live in the spec file that
never ran before today. RPR-39 tampers with `requestObject.nonce` while re-using a valid
`vp_token`; adding a check on a `nonce` echoed in the response payload did not flip it, so
the tampered value appears not to travel on the wire — to be confirmed against the SDK.
