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
| Response | The wallet's `direct_post.jwt`: a JWE containing the SD-JWT VC presentation and its key-binding JWT | Decrypted in memory with the RP key |
| Verification | Issuer signature, trust chain, key binding (`nonce`, `aud`, `sd_hash`), disclosure digests, validity window, revocation status | Nothing written anywhere |
| Result | `Verified(claims)` with only the disclosed claims, or `Rejected(reason)` | Returned to your application; recorded on the transaction |

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

So: the presentation is not retained, the claims briefly are. With the default
`InMemoryTransactionStore` they live in the process heap and expire with the transaction
time to live. They are never written to disk by this library.

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
thing a venue archives instead of a copy of someone's medical paperwork.

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
- **Responses are encrypted, not merely signed.** The IT-Wallet profile requires
  `direct_post.jwt` with ECDH-ES and A256GCM, so the presentation is not readable by
  anything between wallet and verifier.

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
5. **The status list token's signature is not verified yet.** The token is parsed, not
   validated, so its contents are trusted on the strength of TLS and of the fact that the
   URI comes from an already signature-verified credential. Whoever can serve that URI can
   therefore report a revoked credential as valid. This is an integrity gap rather than a
   confidentiality one, it is tracked, and it is fixed before the first stable release.
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
- **Keep receipts, not documents.** If you are still receiving medical certificates by
  email, that is the practice to end — verification at the gate plus a signed receipt is
  both lighter and more defensible than an attachment from two months ago.

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
