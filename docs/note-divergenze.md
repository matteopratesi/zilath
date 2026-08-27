# IT-Wallet vs ARF/EUDI divergences (observed during M0.4)

Recorded against IT-Wallet v1.4.5 (docs/spec-version.md) and PagoPA conformance tool 1.2.1
(`@pagopa/it-wallet-conformance-tool`, wallet version `V1_4`). The EUDI reference verifier
(`eudi-srv-verifier-endpoint`) has been cloned for comparison; a runtime side-by-side is
still pending (tracked on the project board).

## Specification-level divergences

| Topic | ARF / EUDI reference | IT-Wallet v1.4.5 |
|---|---|---|
| Trust model | X.509 chains / `verifier_attestation` | **OpenID Federation**: entity statements, trust chain to a national Trust Anchor, `trust_chain` JWS header for offline validation |
| Credential query | `presentation_definition` (legacy) still common | **`dcql_query` only** |
| Response mode | `direct_post` allowed | **`direct_post.jwt` mandatory**, response always JWE (ECDH-ES P-256, A128GCM/A256GCM) |
| Client identifier | various schemes | only `openid_federation:` and `x509_hash:` prefixes |
| RP metadata | verifier metadata via its own endpoints | `client_metadata` in the JAR must carry `jwks`, `encrypted_response_enc_values_supported`, `vp_formats_supported` (OpenID4VP 1.0 member names) |

## Conformance-tool behaviors stricter than (or beyond) the spec text

- The JAR header schema requires **`x5c` for every client id scheme** in V1_3/V1_4, while the
  spec marks it mandatory only for `x509_hash` (optional with `openid_federation`).
- The local Trust Anchor serves on `https://localhost:3001` but identifies itself as
  `https://trust-anchor.wct.example.org:3001`: chain validation must use the entity id from
  the anchor's own entity configuration, not the URL it is reached at.
- The mock PID (vct `urn:eudi:pid:it:1`) carries its **`trust_chain` in the JWS header**
  (offline scenario): a verifier must support provided-chain validation, not only online
  resolution.
- Wallet **authorization error responses** are posted to the same `response_uri` and the RP
  must acknowledge them with HTTP 200 (`direct_post` semantics).

## Known gaps on our side (tracked as issues on the project board)

1. **Same-device flow** (redirect_uri, `response_code`, status endpoint): explicitly out of
   v0 scope (plan §0); accounts for most of the remaining conformance failures (RPR-19/28/29
   -34/42-45/56-59/69-72/83/84).
2. **RP federation onboarding** (VARCO-33): the RP now publishes its entity configuration
   at `/.well-known/openid-federation` (`federation_entity` + `openid_credential_verifier`
   metadata, attested `request_uris`/`response_uris`, protocol JWKS by value) and the JAR
   carries the RP `trust_chain` header when the federation provides one. What remains is
   the onboarding itself — registration under a superior and the fetch endpoints a real
   federation requires — which needs a counterpart (IPZS test environment or the AgID
   registration procedure, still unpublished).
3. **`metadata_policy` operators** from subordinate statements are not applied by
   `FederationTrustEvaluator` yet.
4. Status list token **signature** is not verified yet (needs the status provider inside the
   trust chain; noted in `OAuthStatusListChecker`).
