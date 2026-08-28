# Releasing to Maven Central

Read this before the first release, not during it.

> **A version published to Maven Central can never be deleted, replaced or amended.** Not by
> you, not by Sonatype. If a release goes out with the wrong artifacts, a broken POM or a
> secret in a jar, the only remedy is to publish another version and live with the first one
> being there forever. That is why nothing in this build uploads anything: Gradle produces a
> bundle locally, and a human uploads it.

## One-time setup

None of this is automated on purpose — each step needs an account or a key that belongs to a
person, not to a build.

### 1. Claim the `dev.zilath` namespace

The groupId is the reverse-DNS form of `zilath.dev`, so the Central Portal verifies it by
asking for a DNS record on that domain.

1. Sign in at <https://central.sonatype.com> and add the namespace `dev.zilath`.
2. The Portal shows a verification key. Add it as a **TXT record on `zilath.dev`**.
3. Wait for propagation, then press verify in the Portal.

Check the record actually resolves before pressing verify:

```sh
dig +short TXT zilath.dev
```

If you ever let `zilath.dev` lapse, the namespace stays yours — Central does not re-verify —
but you would lose the ability to prove it again. Keep the domain renewed.

### 2. Create a Central Portal user token

Account → *Generate User Token*. It gives a username and a password, which are **not** your
account credentials and can be revoked separately. Keep them in the keychain, not in a file
in this repo.

### 3. Create and publish a signing key

Central requires every artifact to carry a detached GPG signature, and it checks the public
key against the public keyservers.

```sh
gpg --full-generate-key                      # RSA 4096 or Ed25519, no expiry shorter than a few years
gpg --list-secret-keys --keyid-format=long   # note the key id
gpg --send-keys --keyserver keys.openpgp.org <KEY_ID>
```

Export the private key in the armored form the build expects:

```sh
gpg --armor --export-secret-keys <KEY_ID>
```

Keep that output in the keychain. **Never** put it in the repo, in an environment file, or
in a CI variable that prints on failure.

## Cutting a release

1. **Decide the version and make it real.** Set it in `build.gradle.kts` (the `subprojects`
   block) — the bundle task refuses to run on a `-SNAPSHOT`.

2. **Make sure the tree is clean and green.**

   ```sh
   ./gradlew build
   git status --porcelain     # must be empty
   ```

3. **Export the signing key for this shell only.**

   ```sh
   export ZILATH_SIGNING_KEY="$(security find-generic-password -s zilath-signing -w)"
   export ZILATH_SIGNING_PASSWORD="$(security find-generic-password -s zilath-signing-pass -w)"
   ```

   Without `ZILATH_SIGNING_KEY` the build simply does not sign, and `centralBundle` refuses
   to produce an unsigned bundle rather than letting you discover it at upload time.

4. **Build the bundle.**

   ```sh
   ./gradlew centralBundle
   ```

   The result is `build/central/zilath-central-bundle.zip`, containing the four library
   modules — `verifier-core`, `verifier-openid4vp`, `verifier-trust-itwallet`,
   `verifier-spring-boot-starter` — each with its jar, sources jar, Dokka javadoc jar, POM
   and signatures. The demo applications are not published.

5. **Look inside the bundle before uploading.** This is the last moment at which anything is
   reversible.

   ```sh
   unzip -l build/central/zilath-central-bundle.zip
   ```

   Check that every artifact has a matching `.asc`, that the version is the one you meant,
   and that nothing from `demo-checkout` or `gate-check` is in there.

6. **Upload.** Either drop the zip in the Portal's *Publish* page, or use the API with the
   user token from step 2:

   ```sh
   curl -sS -X POST https://central.sonatype.com/api/v1/publisher/upload \
     -H "Authorization: Bearer $(printf '%s:%s' "$TOKEN_USER" "$TOKEN_PASS" | base64)" \
     -F bundle=@build/central/zilath-central-bundle.zip
   ```

   The Portal validates the bundle and leaves it in a staged state. **Validation passing is
   not publication.** Review the staged deployment, then release it deliberately.

   The API shape has changed before; if the call is rejected, trust the Portal documentation
   over this file and correct this file afterwards.

7. **Tag and push, only once the release is actually out.**

   ```sh
   git tag -a v<version> -m "v<version>"
   git push origin v<version>
   ```

   Tagging after publication rather than before keeps the repository from claiming a release
   that does not exist.

8. **Set the next development version** back to `-SNAPSHOT` and commit.

## What gets published

| Module | Published |
|---|---|
| `verifier-core` | yes — without its test fixtures |
| `verifier-openid4vp` | yes |
| `verifier-trust-itwallet` | yes |
| `verifier-spring-boot-starter` | yes |
| `demo-checkout`, `gate-check` | no — applications, not artifacts to depend on |

The test fixtures of `verifier-core` are deliberately excluded: they were written for our own
tests, not as a supported API, and publishing them would commit us to keeping them stable
forever. Adding them later is easy; removing them later is impossible.

## Before the first release

Two things are outstanding and should not be released around:

- **VARCO-54** — the status list token's signature is not verified. A first release should
  not go out with a revocation check that can be spoofed.
- The repository is still private. Publishing artifacts whose POM points at a `404` on
  GitHub would be worse than not publishing.
