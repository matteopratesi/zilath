# Zilath

[![build](https://github.com/matteopratesi/zilath/actions/workflows/build.yml/badge.svg)](https://github.com/matteopratesi/zilath/actions/workflows/build.yml)

A Kotlin/JVM library that lets any JVM application act as an **OpenID4VP relying party**
for European digital identity wallets: request a credential from the user's wallet
(cross-device QR or same-device link), receive and cryptographically verify it
(SD-JWT VC), and get back a minimal yes/no outcome — **without ever storing the
credential**. The presented document is never kept. The claims a verification hands over
wait in the transaction store for the application to read them: no read returns them past
the transaction's time to live (five minutes by default), and the default store drops them
within half a minute of it. The signed receipt a venue may keep carries no claim value
([docs/privacy-by-design.md](docs/privacy-by-design.md), §3).

Wallet behavior is a pluggable **profile**: the Italian **IT-Wallet** profile is the
default and the most complete (signed JAR, encrypted `direct_post.jwt`, OpenID
Federation trust), and an **ARF baseline** profile targets EUDI wallets in any member
state. The European Disability Card — the launch use case — is itself an EU instrument
(Directive (EU) 2024/2841, mutual recognition from June 2028).

Born for accessibility rights: letting a person with a disability prove an entitlement
(companion ticket, priority access) online without ever sending health documents to anyone.

> *Zilath* was the chief magistrate of an Etruscan city: the office that ascertained a
> claim and made it binding. That is the whole job of this library — it verifies what a
> public authority has already attested. It never issues a credential, and it never
> decides who qualifies.
>
> Status: pre-alpha — the cross-device flow completes end to end against the official
> PagoPA conformance tool (see [docs/conformance](docs/conformance/)), and the API is
> not frozen yet.
> Target spec: IT-Wallet v1.4.6 — see [docs/spec-version.md](docs/spec-version.md).
>
> **0.3.0 cannot verify a genuine European Disability Card in the production IT-Wallet
> configuration.** The code on `main`, not released yet, verifies a card shaped as
> IT-Wallet 1.4.6 writes it against the production federation's own documents, in a test;
> no card actually issued has been through it. What that test shows and what it does not:
> [SECURITY.md](SECURITY.md#production-readiness).
>
> What this library does with the data it touches, what it keeps and what it cannot
> promise: [docs/privacy-by-design.md](docs/privacy-by-design.md).

## Modules

| Module | Purpose |
|---|---|
| `verifier-core` | Pure JVM credential verification (SD-JWT VC). No framework, no network I/O. |
| `verifier-openid4vp` | Relying-party flow: transactions, request JWT, `direct_post`, replay protection. |
| `verifier-trust-itwallet` | OpenID Federation trust chain evaluation, `metadata_policy`. |
| `verifier-spring-boot-starter` | Spring Boot auto-configuration and endpoints. |
| `demo-checkout` | Demo app: fake event checkout unlocking a companion ticket. |

## Using it

Published to Maven Central as `dev.zilath`. Take `verifier-spring-boot-starter` for a Spring
Boot application — it brings the rest with it — or `verifier-core` alone to verify
credentials with no framework and no network I/O.

```kotlin
dependencies {
    implementation("dev.zilath:verifier-spring-boot-starter:0.3.0")
}
```

Artifacts are signed with key [`392ABDC140E3041A`](https://keys.openpgp.org/search?q=392ABDC140E3041A).

**The API is not frozen.** This is a `0.x` line: anything can still move between minor
versions, and the [changelog](CHANGELOG.md) calls out separately every change that alters
what a verifier accepts or rejects — those are the ones that can quietly let something
through.

Coming from **0.2.0**: `Verified.claims` no longer carries the issuer envelope. `iat`, `exp`,
`nbf`, `cnf`, `status`, `sub`, `aud` and `jti` are stripped — each is stable per credential,
so passing them on would let anything downstream link two verifications of the same person.
Code that read `iat` or `exp` from the claims must stop.

The rest of this section describes `main`, which is ahead of 0.3.0 and breaks its API in
places: the changelog's *Unreleased* section lists every difference.

### Reading the outcome

`start()` returns a `StartedTransaction`. Its id travels in the QR code, in `state` and in
the request and response URIs, so it is **public**: anyone who sees the checkout's screen,
or the link a same-device user was sent, has it. It lets a wallet post a response; it never
reads an outcome. `awaitOutcome(txId, pollToken)` does, with the `PollToken` that `start()`
returned to the checkout alone or, same-device, the one `consumeResponseCode` hands the
user-agent that came back with the response code. Keep the token in a server-side session
or an HttpOnly cookie, never in a URL or a log.

`FlowOutcome.Verified` means that the issuer is trusted — under a federation, for the
credential type presented — and that type is the one requested; that the signature, the
key binding and the validity window check out; that the credential is not revoked, when it
carries a status reference; and that the claims the query asked for are present (all of
them, or one combination its `claim_sets` allows), each equal to one of its `values` when
the query names any. A presentation that falls short is rejected, `QUERY_NOT_SATISFIED`.
Without `values`, judging the value is the application's job: a card disclosing
`constant_attendance_allowance: false` is verified, and is not an entitlement — the demo
checks the value itself.

`Verified.claims` holds the requested claims that are present, plus `iss` and `vct`; for a
query without `claims`, what the holder disclosed, plus `iss` and `vct`. Nothing else: not
what a wallet disclosed beyond the request, not an issuer's plaintext claim nobody asked for,
never the issuer envelope (`iat`, `exp`, `cnf`, `status` and the rest).

### Revocation

A credential that carries a `status` reference is checked by the application's
`StatusChecker`; one without it is not revocable, and the checker is never called for it.
The library's checker for Token Status Lists is `OAuthStatusListChecker`, and the only piece
it needs from the application is a `StatusListFetcher`, the network access: declare a
`StatusListFetcher` bean and no `StatusChecker`, and the starter configures an
`OAuthStatusListChecker` around it. What the checker validates, and what the fetcher must
enforce on its own — timeouts, response size, redirects, private address ranges — is in
[SECURITY.md](SECURITY.md) and [docs/privacy-by-design.md](docs/privacy-by-design.md) §5.

**A `StatusChecker` that always answers `VALID` switches revocation off.** It is only ever
called for a credential that carries a status reference, so a constant `VALID` is the wrong
answer for every revoked one. The demo's example checker answers `UNKNOWN` instead, which
rejects every credential that carries a status reference.

### With Spring Security

With `spring-boot-starter-security` on the classpath, the default configuration asks every
request for a login and every POST for a CSRF token. A wallet has neither, and every holder
would be turned away. Give the wallet-facing paths a chain of their own, ahead of the
application's:

```kotlin
@Bean
@Order(1)
fun walletEndpoints(http: HttpSecurity): SecurityFilterChain =
    http
        .securityMatcher("/openid4vp/request/**", "/openid4vp/response/**", "/.well-known/openid-federation")
        .authorizeHttpRequests { it.anyRequest().permitAll() }
        .csrf { it.ignoringRequestMatchers("/openid4vp/request/**", "/openid4vp/response/**") }
        .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
        .build()
```

Why this shape:

- The wallet holds no session and no CSRF token. Its requests are authorised by the
  transaction id, the nonce and the encrypted response, not by an ambient credential such as
  a session cookie, which is what CSRF protection guards; so these paths go without it, and
  no session is created for them.
- **Never `csrf.disable()` or `permitAll()` on the whole application** to make the wallet
  work: that strips the protection from every page that does rely on a session. Declaring
  a `SecurityFilterChain` bean also replaces Spring Boot's default one, so the rest of the
  application needs a chain of its own, at a later order.
- `securityMatcher` keeps Spring Security's default response headers on these paths, where
  `web.ignoring()` would take the paths out of Spring Security altogether, and the
  `Cache-Control: no-store` the endpoints set stays.
- The request object is fetched by GET or by POST: the starter announces
  `request_uri_method=post`, so a wallet may POST to `/openid4vp/request/{txId}`, and that
  path is exempt from CSRF as the response path is.
- `/.well-known/openid-federation` is the relying party's entity configuration, which the
  starter serves when `zilath.openid4vp.federation.entity-id` is set (and refuses to start
  if the relying party configuration then has no federation identity). Federations and
  wallets read it anonymously.

## Build

Requires JDK 21 (a Gradle toolchain will pick it up).

```sh
./gradlew build
```

## Try the demo

A fake event checkout that unlocks a companion ticket by presenting the test PID from a
wallet, with the PagoPA conformance tool acting as the wallet.

**Node >= 22.13 is required** (or any Node 23+) — the tool imports `node:sqlite`, which
became available unflagged in 22.13, and on a runtime without it the tool hangs rather than
failing cleanly. With `nvm`: `source ~/.nvm/nvm.sh && nvm use 22`, then run the steps below
from that same shell. The script checks this for you before doing anything else.

1. Generate a self-signed RP certificate (the wallet requires the `x509_hash` scheme):

   ```sh
   mkdir -p demo-keys && cd demo-keys && \
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
     -keyout rp-key.pem -out rp-cert.pem -days 30 -nodes -subj "/CN=localhost" && \
   cat rp-cert.pem rp-key.pem > rp-combined.pem && cd ..
   ```

2. Start the app (trust is bootstrapped against the tool's local anchor):

   ```sh
   ZILATH_TRUST_ANCHOR_ID=https://localhost:3001 ZILATH_TRUST_ANCHOR_TOFU=true \
   ZILATH_INSECURE_TLS=true ZILATH_PID_VCT=urn:eudi:pid:it:1 \
   ZILATH_RP_PEM_PATH=$PWD/demo-keys/rp-combined.pem \
   ./gradlew :demo-checkout:bootRun
   ```

3. Open <http://localhost:8080/demo>, click "Ho diritto al biglietto accompagnatore" and
   copy the transaction id shown on the QR page.
4. Let the test wallet present the PID (transactions live 5 minutes, so use a fresh id):

   ```sh
   ./scripts/run-demo-wallet.sh <transactionId>
   ```

   The script runs only the conformance tool's happy-flow tests, and there is a reason:
   the other suites deliberately post authorization *error* responses, and an OpenID4VP
   transaction is single-use — the first error response consumes its nonce, so everything
   after it correctly gets `REPLAY` and the happy flow finds the request endpoint already
   closed. One transaction cannot serve the whole suite. For the full run, see
   [docs/conformance](docs/conformance/).

   Some conformance assertions fail even in the happy flow: they are the known gaps in
   [docs/note-divergenze.md](docs/note-divergenze.md), not regressions. What decides
   whether the presentation went through is the transaction status, which the script
   reports at the end.

5. The page turns into a nominative companion ticket; the "ricevuta di verifica" link is
   the signed receipt a venue would keep — outcome, the venue's entitlement verdict and the
   time, never a document or a claim value. The demo signs it from the ticket page, once its
   entitlement rule has been applied.

   The demo pages answer only the browser that started the transaction, which holds its
   session cookie: open the ticket and the receipt there.

### Simulated CED mode

The same checkout can ask for a **simulated European Disability Card** instead of the PID —
the ticket then unlocks on the *entitlement*, not on identity. The real CED has been a
production IT-Wallet credential on app IO since December 2024: configuration
`dc_sd_jwt_EuropeanDisabilityCard` of the issuer `https://eaa.wallet.ipzs.it/1-0`, whose
metadata advertises `vct: https://ta.wallet.ipzs.it/vct/v1.0.0/europeandisabilitycard`
(verified against the production entity statement on 2026-08-25, and present in the one
served on 2026-09-24 that the tests replay; the same URL serves the credential type
metadata — newer issuer versions may adopt the spec's `urn:eudi:<type>:it:1` vct convention
instead, and since the vct is compared exactly, `vct_values` must name the one the cards
carry).

Two things stand between that card and a private relying party. Production verification by
private relying parties does not exist yet. And the library was not ready for it either:
**0.3.0 cannot verify any genuine card of that issuer**, even once verification is allowed
— the production federation's trust chain ended untrusted, and past that a status list
token in the IT-Wallet form was refused. The code on `main`, not released yet, verifies a
card shaped as IT-Wallet 1.4.6 writes it against the production federation's documents, in
a test with a synthetic card; but the issuer advertises status assertion and attestation
endpoints rather than a status list, and a card whose status carries only an assertion or
an attestation is still rejected. The details, and what else the test does not show, are
in [SECURITY.md](SECURITY.md#production-readiness).

The simulation therefore mirrors the real claim names (`given_name`, `family_name`,
`constant_attendance_allowance`, `expiry_date`) under an openly fake vct and federation — it
never impersonates the real issuer — and discloses only that minimized subset (never
portrait, birth date or document number). Note the semantic limit of the real claim:
`constant_attendance_allowance` covers the attendance allowance, not every card printed with
the companion "A".

```sh
./scripts/run-ced-wallet.sh init
ZILATH_TRUST_ANCHOR_ID=https://anchor.ced-sim.zilath.invalid \
ZILATH_TRUST_ANCHOR_JWKS_PATH=$PWD/demo-keys/ced-sim/anchor-jwks.json \
ZILATH_DEMO_CREDENTIAL_MODE=ced-sim ./gradlew :demo-checkout:bootRun
# then, with the transaction id from the QR page:
./scripts/run-ced-wallet.sh <transactionId>
```

For the full conformance run against this RP, see [docs/conformance](docs/conformance/).

## Contributing

Issues and pull requests are welcome — read [CONTRIBUTING.md](CONTRIBUTING.md) first, in
particular the red lines the project will not cross. Contributions are covered by the
[Contributor License Agreement](CLA.md), accepted by signing off your commits
(`git commit -s`).

## How this was built

This library was written with the assistance of a large language model, under human
direction and review. Where that assistance was used, and what was decided rather than
generated, is recorded in [docs/genai-provenance.md](docs/genai-provenance.md) — kept
current as work happens, because it cannot be reconstructed afterwards.

## Security

Found a vulnerability? **Do not open a public issue** — see [SECURITY.md](SECURITY.md) for
the private reporting channel, the boundaries this library deliberately does not defend,
and the current state of cryptographic review.

## License

AGPL-3.0, with a commercial licence available as an alternative. What separates the two is
not whether you make money from it: it is **whether the software that incorporates the
library is open or closed**.

The AGPL does not forbid commercial use. It is, however, strong copyleft, and incorporating
the library into an application is generally understood to produce a work based on it:
conveying that application means giving recipients its Corresponding Source under the same
licence, and — this is what separates the AGPL from the GPL — letting users interact with a
modified work over a network means offering them that source too, even though no copy was
ever distributed. So:

- **open software** — use it freely and at no cost, including inside a paid service;
- **closed software** — the AGPL terms cannot be met, and the commercial licence applies.

The second case covers proprietary ticketing and venue systems, which is the setting this
library was written for. The commercial licence is the project's only intended source of
revenue: contact the author.

Where that cost falls is a property of the model rather than an accident of it — on
organisations that choose to keep their own software closed. **The person being verified
never pays and is never metered.** Not because the price was set that way, but because it
is a stated constraint of the project: section 4 of the [CLA](CLA.md). The project may not
be transferred to anyone who has not accepted that section in writing — and a transfer made
without it does not carry the relicensing right along with it.

The commercial licence only ever exists *alongside* the open one. Every release stays
available under the AGPL-3.0, or another licence approved by the Open Source Initiative
granting at least the same freedoms, and no feature is withheld from it.
