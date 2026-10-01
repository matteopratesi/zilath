# Target specification version

- **IT-Wallet technical specifications: v1.4.7 LTS** (released 2026-09-22), as published at
  https://italia.github.io/eid-wallet-it-docs/releases/1.4.7/it/ — bumped from v1.4.6 on
  2026-10-01 (logged decision): the 1.4.6→1.4.7 delta leaves the RP flow requirements
  below unchanged. The remote flow, the relying party's entity configuration, credential
  revocation, the credential data model and the cryptographic algorithms are word for word
  the same; in the trust infrastructure the entity statement tables are the same, and a
  leaf's `federation_entity` metadata may now give `organization_uri` in place of
  `homepage_uri` (the library publishes `homepage_uri`, which stays valid). The rule texts
  quoted in the code as "1.4.6" are the same in 1.4.7. What it does change: PAR (`typ`, `scope`) and the federation entity type
  `wallet_solution`, renamed `openid_wallet_provider`, both breaking and both on the issuer
  and wallet provider side, where this library reads neither; a new Identity Matching section
  for what a relying party does with a verified PID or IT-Wallet ID (RPR-115, RPR-116), which
  is the application's to do, not the library's; test ATT-004, which now names the
  algorithms a signature may use: only those listed as MUST or RECOMMENDED in the
  Cryptographic Algorithms section are accepted, the others rejected; and test ATT-006,
  which now asks keys to provide at least 128 bits of security strength (NIST SP 800-57
  Part 1), which is 3072 bits for RSA. The library follows both: see the CHANGELOG.
  The 1.4.x line is LTS (EOL when IT-Wallet is notified as EUDIW-compliant, at the latest
  ~August 2027); further breaking changes live on the `eudiw`/1.5 branch and will be
  absorbed behind the WalletProfile seam.
- All profile decisions (request/response modes, trust chain format, credential formats)
  MUST be taken against this version. Upgrading the target version is a logged decision.
## RP flow requirements of v1.4.x (recorded against v1.4.5)

- `response_mode=direct_post.jwt` is MANDATORY for both same-device and cross-device flows:
  the wallet response is always an encrypted JWE (ECDH-ES on P-256 with A128GCM/A256GCM,
  A256GCM preferred). The RP advertises its encryption key in `client_metadata.jwks`
  together with `authorization_encrypted_response_alg/enc`.
- The request object is a JAR typed `oauth-authz-req+jwt`, signed ES256 with `kid`;
  required claims: `client_id`, `response_type=vp_token`, `response_mode`, `response_uri`,
  `nonce` (min 32 chars), `dcql_query` (NOT presentation_definition), `client_metadata`,
  `iss`, `iat`, `exp`; `state` recommended.
- QR payload: `openid4vp://` or `haip-vp://` scheme (or HTTPS universal link) with
  `client_id` and `request_uri`; `request_uri_method` optional (GET when absent).
- Client id prefixes `openid_federation:` / `x509_hash:` are supported, and the trust
  chain travels in the JAR header when the federation provides one.
- The integration tests simulate the wallet with `eudi-lib-jvm-sdjwt-kt` (issuance + key
  binding) rather than `eudi-lib-jvm-siop-openid4vp-kt`: the siop library is a full wallet
  stack carrying its own HTTP client and trust machinery, which makes it unsuitable for
  hermetic in-process tests. The conformance tool covers the real wallet side.
