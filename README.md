# varco-verifier

[![build](https://github.com/matteopratesi/varco-verifier/actions/workflows/build.yml/badge.svg)](https://github.com/matteopratesi/varco-verifier/actions/workflows/build.yml)

A Kotlin/JVM library that lets any JVM application act as an **OpenID4VP relying party with
the Italian IT-Wallet profile**: request a credential from the user's wallet (cross-device
QR flow), receive and cryptographically verify it (SD-JWT VC), and get back a minimal
yes/no outcome — **without ever storing anything**.

Born for accessibility rights: letting a person with a disability prove an entitlement
(companion ticket, priority access) online without ever sending health documents to anyone.

> Working name. Status: pre-alpha, milestone M0.1 (project skeleton).
> Target spec: IT-Wallet v1.4.5 — see [docs/spec-version.md](docs/spec-version.md).

## Modules

| Module | Purpose |
|---|---|
| `verifier-core` | Pure JVM credential verification (SD-JWT VC). No framework, no network I/O. |
| `verifier-openid4vp` | Relying-party flow: transactions, request JWT, `direct_post`, replay protection. |
| `verifier-trust-itwallet` | OpenID Federation trust chain evaluation, IT-Wallet profile. |
| `verifier-spring-boot-starter` | Spring Boot auto-configuration and endpoints. |
| `demo-checkout` | Demo app: fake event checkout unlocking a companion ticket. |

## Build

Requires JDK 21 (a Gradle toolchain will pick it up).

```sh
./gradlew build
```

## License

AGPL-3.0 — free to use in open-source software. For embedding in closed-source commercial
products, a commercial license is available: contact the author.
