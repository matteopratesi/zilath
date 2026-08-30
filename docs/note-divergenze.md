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

1. **Same-device flow**: implemented in the library — `FlowMode.SAME_DEVICE`
   transactions, wallet-response ack carrying `redirect_uri` with a single-use
   `response_code` (also on wallet cancellation, RPR-59), `consumeResponseCode` exchange
   for the return leg, callback base in `RpEndpoints`/starter properties, demo `/demo/cb`
   endpoint plus a same-device link on the event page. A conformance re-run against the
   PagoPA tool is still pending to confirm which RPR failures clear.
2. **RP federation onboarding**: the RP now publishes its entity configuration
   at `/.well-known/openid-federation` (`federation_entity` + `openid_credential_verifier`
   metadata, attested `request_uris`/`response_uris`, protocol JWKS by value) and the JAR
   carries the RP `trust_chain` header when the federation provides one. What remains is
   the onboarding itself — registration under a superior and the fetch endpoints a real
   federation requires — which needs a counterpart (IPZS test environment or the AgID
   registration procedure, still unpublished).
3. **`metadata_policy` operators**: applied — `value`, `add`, `default`,
   `one_of`, `subset_of`, `superset_of`, `essential` are merged anchor-first and resolved
   against the leaf metadata; the credential keys come from the resolved metadata.
4. **KB-JWT audience**: the two specifications disagree on whether the audience
   carries the Client Identifier Prefix. OpenID4VP 1.0 (App. B.3.6) says it is the Client
   Identifier and its example keeps the prefix; the IT-Wallet rules say it must match the
   "Relying Party unique entity identifier", which reads as the stripped form — and the
   conformance tool implements OpenID4VP in its wallet and the profile wording in RPR-105/
   106, so it contradicts itself. Reported: pagopa/wallet-conformance-test#221. Until it is
   settled the verifier accepts BOTH forms of its own identifier (never a third party's).
5. Status list tokens are validated per draft §8.3 — signature, `typ`, `sub`, expiry — but
   only when signed by the **issuer of the credential being checked**. The draft permits a
   separate Status Issuer (§11.3) and mandates no way to establish trust in one, so a token
   from any other entity is `UNKNOWN`. Supporting a third-party status issuer needs a policy
   decision and configuration; it is not a default.
6. The issuer JWT's and key-binding JWT's `typ` headers are checked only when PRESENT. The
   specification requires them, but our own vectors omit them and there is no evidence yet
   about the production IT-Wallet issuer — and rejecting a genuine credential is, on this
   project, as costly as accepting a forged one. Revisit with a real credential in hand.
