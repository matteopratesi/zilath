# Target specification version

- **IT-Wallet technical specifications: v1.4.6 LTS** (released 2026-08-06), as published at
  https://italia.github.io/eid-wallet-it-docs/releases/1.4.6/it/ — bumped from v1.4.5 on
  2026-08-25 (logged decision): the 1.4.5→1.4.6 delta is documentation
  plus the IT-Wallet ID data model, with no changes to the RP flow requirements below.
  The 1.4.x line is LTS (EOL when IT-Wallet is notified as EUDIW-compliant, at the latest
  ~August 2027); breaking changes live on the `eudiw`/1.5 branch and will be absorbed
  behind the WalletProfile seam.
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
