# Conformance run — 2026-08-27 (after VARCO-32/33/34)

- Tool: `@pagopa/it-wallet-conformance-tool` **1.2.1**, `test:presentation`, wallet
  version **V1_4**, same setup as [2026-08-24](../2026-08-24/README.md).
- Result: **33 passed, 36 failed, 22 skipped** — unchanged from the 2026-08-24 run,
  and the cross-device happy flow still completes end to end.

## Why the numbers did not move (honest read)

The three gap features now exist in the library — same-device flow with
`redirect_uri`/`response_code` (PR #12), the RP entity configuration (PR #10),
`metadata_policy` (PR #11, wallet-side, not exercised by these tests) — but the
conformance harness does not reach them yet:

1. `/conformance/start` creates **cross-device** transactions, so the wallet-response
   ack never carries `redirect_uri`: every same-device/redirect/response_code/status
   test (RPR-19/28-34/42-45/56-59/69-72/83/84/108/109/112) still fails.
2. With the `x509_hash` scheme the tool reads the verifier metadata from the JAR
   `client_metadata`, not from `/.well-known/openid-federation`: the attestation
   checks (RPR-01/03/82/85/86/95) need those members (`request_uris`, `response_uris`,
   `redirect_uris`, `response_types_supported`, status endpoint) published THERE.

## Follow-up (tracked on the project board)

Wire the conformance harness to the new features: run the tool-driven transactions in
SAME_DEVICE mode (or expose a mode switch on `/conformance/start`), enrich the profile
`client_metadata` with the members the tool attests, and expose the session-status
endpoint shape the tool expects (to be read from the tool's test sources).
