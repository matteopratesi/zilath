# IT-Wallet federation documents, as served on 2026-09-24

Real, unmodified documents of the production IT-Wallet federation, fetched with plain
read-only GET requests on 2026-09-24 during the fourth internal review. They are the
signed originals: not a byte was changed, so every signature still verifies, and they
cannot be edited without breaking it.

| File | Fetched from | Bytes | Validity (`iat` – `exp`, epoch seconds) |
|---|---|---|---|
| `ta-entity-configuration.jwt` | `https://ta.wallet.ipzs.it/.well-known/openid-federation` | 4243 | 1790259439 – 1790345839 |
| `ta-statement-about-eaa-1-0.jwt` | `https://ta.wallet.ipzs.it/federation_fetch_endpoint?sub=https%3A%2F%2Feaa.wallet.ipzs.it%2F1-0` | 8112 | 1790235621 – 1790322021 |
| `eaa-1-0-entity-configuration.jwt` | `https://eaa.wallet.ipzs.it/1-0/.well-known/openid-federation` | 39668 | 1790282054 – 1821818054 |
| `ta-list.json` | `https://ta.wallet.ipzs.it/list` | 272 | — |

`https://eaa.wallet.ipzs.it/1-0` is the issuer of the European Disability Card that the
trust anchor lists; its credential signing key has kid
`dcb47a053c6c725838f6a5ea8855558f90ee3cf97eeb8a94fe7e6a0e364d3b27`.

Tests that use them fix the clock at **1790290000**, inside all three validity windows:
the subordinate statement lives 24 hours, so a test on a live clock would pass for one day
and fail forever after. Why they are here: before 0.4.0 the library turned this chain,
exactly as published, into `Untrusted` — a `metadata_policy` for `wallet_provider` applied
to an entity that publishes no such metadata — so no genuine credential of this issuer
could verify. A test on synthetic fixtures had not seen it, because the fixtures were
written by the same hands as the code.

The contact addresses inside are the ones the organisations publish in their federation
metadata for this purpose; they identify offices, not people.
