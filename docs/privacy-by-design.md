# Privacy by design

What this library does with the data it touches, what it keeps, and — the part most such
documents leave out — what it cannot promise. Written for the person who has to decide
whether to put Zilath in front of real users, and for the DPO who will ask them about it.

Every claim here is checkable against the source. File references are given so you do not
have to take any of it on trust; that is the whole point of shipping under AGPL-3.0.

## 1. Where this library sits

Zilath is **software, not a service**. There is no Zilath server, no account, no API key,
no telemetry, and no network call to anything the project controls. You compile it into
your application and it runs entirely inside your infrastructure.

In GDPR terms that means the authors of this library are neither controller nor processor
for your verifications: no personal data ever reaches them. **You** — the venue, the
ticketing platform, whoever deploys it — are the controller. This document does not make
your compliance decisions; it tells you precisely what the component under your control
does, so that you can make them.

## 2. What flows through a verification

A single verification, end to end:

| Step | What is handled | Where it goes |
|---|---|---|
| Request | A DCQL query naming the credential type and the claim paths you ask for | Signed into the request object (JAR) the wallet fetches |
| Response | The wallet's response, carrying the SD-JWT VC presentation and its key-binding JWT. **Encrypted only on profiles that require it** — see below | Decrypted or parsed in memory; never written |
| Verification | Issuer signature, trust chain, key binding (`nonce`, `aud`, `sd_hash`), disclosure digests, validity window, revocation status | Nothing written anywhere |
| Result | `Verified(claims)` with only the disclosed claims, or `Rejected(reason)` | Returned to your application; recorded on the transaction |

**Whether the response is encrypted depends on the profile you select.** `ItWalletProfile`,
the default, mandates `direct_post.jwt`: the response is a JWE (ECDH-ES + A256GCM) and is
unreadable to anything between wallet and verifier. `ArfBaselineProfile` uses plain
`direct_post`, so on that profile the presentation is protected by TLS alone, exactly like
any other form post. If you switch profiles, this is the property you are switching.

The credential itself — the issuer-signed JWT, the disclosures, the key-binding JWT — is
never written down. It exists as a local variable for the duration of one call and is
gone when that call returns.

**Selective disclosure is the mechanism that keeps this small.** You ask for claim paths
in the DCQL query; the wallet discloses those and withholds the rest. Ask for a boolean
entitlement and an expiry date, and a boolean and a date are what you get — the diagnosis,
the percentage of invalidity and the medical record are not withheld by our good manners,
they are never transmitted.

## 3. What is retained, and for how long

This is the section that matters, so it is stated plainly rather than favourably.

**The transaction store** holds, per in-flight verification: the transaction id, the nonce,
the state, the creation timestamp, the request that was made, the flow mode, the
same-device response code where applicable, and **the outcome**. For a successful
verification the outcome carries the **disclosed claims** — they have to survive between
the wallet's POST and your application's read of `awaitOutcome`, because those are two
separate HTTP exchanges.

The outcome is retained whole, so for a rejection what persists is the reason code **and
`detail`**, for the same lifetime. Almost every `detail` is a fixed string from this
library, with one exception worth knowing: if you supply your own `TrustEvaluator`, the
text your implementation puts in `TrustDecision.Untrusted(reason)` is passed straight
through and stored with the transaction. Keep personal data out of it. A custom
`StatusChecker` cannot do this — it returns an enum, and the `detail` for a status failure
is written here.

So: the presentation is not retained, the claims and the diagnostic text briefly are. With
the default `InMemoryTransactionStore` they live in the process heap and expire with the
transaction time to live. They are never written to disk by this library.

**If you plug in a shared store** — Redis, a database, anything that outlives the
process — you are putting those claims on that infrastructure, and it becomes part of your
processing: encryption at rest, no persistence to disk where avoidable, no backups of that
keyspace, retention no longer than the transaction. The `TransactionStore` interface exists
so you can do this; the consequences are yours.

**Verification receipts** (`VerificationReceipts`) are the artifact designed to be kept.
A receipt is a signed JWT carrying: the issuer (your client id), the transaction id as
`jti`, the issue time, `outcome` (`verified` or `rejected`), `entitled` (a boolean), the
claim paths that were **requested**, and a SHA-256 hash of the request. It records that a
verification happened and how it came out. **It contains no claim values**, so it is the
thing a venue archives instead of a copy of someone's medical paperwork — under the
retention rules in §6, because a receipt linked to a person is still personal data.

The `gate-check` module issues the same kind of outcome-only receipt for in-person checks.

## 4. Design decisions behind the properties

- **The nonce is single-use.** A replayed response is rejected as `REPLAY`. Beyond replay
  protection this means nothing in the protocol carries across transactions: there is no
  identifier that would let two verifications of the same person be linked by this library.
- **No counters, no history, no profiles.** There is no per-person state of any kind, not
  even for abuse prevention. That is a deliberate refusal, not an omission.
- **Rejection reasons are coarse by design.** `RejectionReason` is a small enum of outcome
  categories — no claim values, nothing about the credential's content, nothing that turns
  the endpoint into a probe for what a person's credential says.
- **Diagnostic detail stays server-side at the HTTP boundary.** The Spring endpoint returns
  the reason code to the wallet and keeps `detail` in the log.
- **On the IT-Wallet profile, responses are encrypted and not merely signed.**
  `direct_post.jwt` with ECDH-ES and A256GCM: the presentation is unreadable to anything
  between wallet and verifier. This is a property of that profile, not of the library —
  `ArfBaselineProfile` posts in the clear over TLS.

## 5. Known limits

An honest list is more useful than a short one.

1. **Disclosed claims sit in the transaction store for the transaction's lifetime.** See
   §3. Unavoidable in a polling architecture; bounded, but not zero.
2. **`VerificationResult.Rejected.detail` travels with the result.** It is diagnostic text,
   not a log-only string: a caller holding the result can read it. Do not surface it to the
   person at the checkout, and do not put it in anything user-facing.
3. **Once we hand you the claims, what happens to them is yours.** `Verified(claims)` is a
   value in your process. This library cannot prevent your application from logging it,
   storing it, or sending it somewhere. Nothing here substitutes for your own review of
   what you do with the result.
4. **Revocation checking leaks metadata to the status provider.** Fetching a status list
   tells whoever serves it that someone is checking a credential at that moment. Status
   lists are designed so that the individual index is hidden in a large list, which is the
   mitigation the format provides, but the fetch itself is observable. Consider caching if
   your volumes make the timing meaningful.
5. **`StatusListFetcher` is yours, and this library cannot see past it.** The status list
   token is now fully validated — signature against the issuer's trusted keys, `typ`, `sub`
   against the referenced URI, and expiry — so a tampered or forged list is `UNKNOWN` rather
   than believed. What the library still cannot do is police the transport: your fetcher
   enforces TLS and certificate validation, or nothing does.

   Two things to get right in that fetcher. **Set
   aggressive connect and read timeouts**: the URI comes from the credential, so a slow or
   unreachable status endpoint stalls a checkout, and TLS does nothing to bound that wait —
   the failure then degrades to `UNKNOWN`, which is a rejection, so a hanging endpoint
   turns into denied entitlements. **And decide what your fetcher is allowed to reach**: it
   dereferences a URL that arrived inside a credential. The verification order limits this
   — trust chain and issuer signature are checked before the status call, so the URI comes
   from an issuer you already trust — but a fetcher able to reach arbitrary hosts is one
   compromised issuer away from being a request-forgery tool inside your network. An
   allow-list of expected status hosts costs nothing.
6. **Pre-alpha.** The API is not frozen and this library has not been independently audited.

## 6. What you still have to do

Zilath handles the cryptography and the minimisation. It does not handle your obligations:

- **Treat the outcome as special-category data.** A "yes" on an accessibility entitlement
  reveals the existence of a disability. The CJEU has held that data indirectly revealing
  special-category information falls under Article 9 (Case C-184/20). Minimisation is what
  this library gives you; it is not reclassification.
- **Establish your legal basis**, provide your information notice, and assess whether a
  DPIA is required for your deployment.
- **Do not ask for more claims than the entitlement needs.** The DCQL query is yours to
  write, and the library will faithfully request whatever you put in it. The smallest query
  that answers your question is the one to send.
- **Keep receipts instead of documents — but keep them as personal data.** A receipt
  carries no claim values, and that is not the same as being anonymous. The moment you
  file it against an order, a name or a seat, it says that this person holds an
  accessibility entitlement, and the `requested_claims` paths say which health-related
  attribute you asked about. By the same reasoning as above (C-184/20), that is
  special-category data. So: a defined retention period tied to the event and its
  accounting obligations, access limited to who needs it, deletion when the period ends —
  and no receipt archive that quietly becomes a register of who is disabled.

  Said plainly, because the temptation is real: receipts exist so you can prove a check
  happened if someone contests it, not so you can build a list. If you are still receiving
  medical certificates by email, that is the practice to end — a signed receipt is lighter
  and far more defensible than an attachment from two months ago.

## 7. Verifying these claims

| Claim | Where to look |
|---|---|
| The presentation is not retained | `verifier-core/.../SdJwtVcCredentialVerifier.kt` |
| What a transaction holds | `verifier-openid4vp/.../TransactionStore.kt` |
| What a receipt contains | `verifier-openid4vp/.../VerificationReceipts.kt` |
| Reason codes carry no content | `verifier-core/.../CredentialVerifier.kt`, `RejectionReason` |
| Detail is kept server-side | `verifier-spring-boot-starter/.../OpenId4VpController.kt` |
| Nonce single use, replay rejected | `verifier-openid4vp/.../OpenId4VpVerificationFlow.kt` |
| No outbound calls to the project | grep the four library modules for any HTTP client — there are none. Every network access goes through `FederationFetcher` and `StatusListFetcher`, interfaces you implement and inject. (The `demo-checkout` app does make HTTP calls; it is an example, not a published artifact.) |

## References

- Regulation (EU) 2016/679, Articles 5(1)(c) and 9
- CJEU, Case C-184/20 (OT, 1 August 2022) — data indirectly revealing special categories
- Garante per la protezione dei dati personali, opinion no. 368 of 14 October 2021 on the
  European Disability Card (doc. web 9716806): service providers access, by default, only
  the information indispensable to the service
- Garante, decision of 13 May 2010 (doc. web 1729156): showing a document is enough,
  keeping a copy is not permitted
- OpenID4VP 1.0; IT-Wallet technical rules v1.4.6; Directive (EU) 2024/2841
