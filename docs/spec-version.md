# Target specification version

- **IT-Wallet technical specifications: v1.4.5** (last updated 2026-08-05), as published at
  https://italia.github.io/eid-wallet-it-docs/releases/1.4.5/it/ — pinned on 2026-08-24
  per the project plan (varco repo, docs/03 §5-M0.1).
- All profile decisions (request/response modes, trust chain format, credential formats)
  MUST be taken against this version. Upgrading the target version is a logged decision.
## RP flow requirements of v1.4.5 (recorded during M0.3)

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
- Client id prefixes `openid_federation:` / `x509_hash:` and the trust chain land in M0.4;
  until then `client_id` is an opaque configured string.
- Deviation from the plan DoD (docs/03 §5-M0.3): the integration test simulates the wallet
  with `eudi-lib-jvm-sdjwt-kt` (issuance + key binding) instead of
  `eudi-lib-jvm-siop-openid4vp-kt` — the siop library is a full wallet stack with its own
  HTTP and trust machinery, unsuitable for hermetic in-process tests against an RP whose
  trust chain does not exist yet (M0.4). Recorded in the project log.
