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
account credentials and can be revoked and regenerated without touching the account.

The Portal hands them over as an XML snippet for `~/.m2/settings.xml`. **Ignore the XML.**
That file is Maven's, this build is Gradle, and nothing here reads it — creating it would
put two credentials in cleartext on disk for no benefit. Take the two values out and put
them in the keychain instead. These prompt for the value, so it stays out of shell history:

```sh
security add-generic-password -a "$USER" -s zilath-central-user -w
security add-generic-password -a "$USER" -s zilath-central-pass -w
```

Then close the page without saving the snippet anywhere. If the values are ever lost they
cannot be recovered — regenerate the token, which takes seconds.

### 3. Create and publish a signing key

Central requires every artifact to carry a detached GPG signature, and it checks the public
key against the public keyservers.

Generate it **yourself**, in your own terminal — the passphrase is the whole point of the
key, and a signing key whose passphrase someone else chose is not your signature.

```sh
gpg --batch --gen-key gpg-release-key.params   # prompts for the passphrase, and only that
gpg --list-secret-keys --keyid-format=long     # note the key id and the fingerprint
gpg --send-keys --keyserver keys.openpgp.org <KEY_ID>
```

RSA 4096, sign-only, three years. RSA rather than Ed25519 because what matters here is that
the signature verifies in whatever tool meets the artifact, forever; expiry is safe because
signatures made while the key was valid stay valid, and an expired key fails the bundle
*before* an upload rather than after.

The user id goes on a public keyserver and stays there. Decide the name and email before
generating, not after.

Store the private key where the release build reads it from:

```sh
gpg --armor --export-secret-keys <KEY_ID> | \
  security add-generic-password -a "$USER" -s zilath-signing -w -
security add-generic-password -a "$USER" -s zilath-signing-pass -w   # the passphrase
```

**Never** put it in the repo, in an environment file, or in a CI variable that prints on
failure.

#### Back up two files, in two different places

```
~/.gnupg/private-keys-v1.d/          the private key material
~/.gnupg/openpgp-revocs.d/<FP>.rev   the revocation certificate, created automatically
```

Do not back up those directories by copying them. Export instead — an export is one
self-contained file that restores on any machine, while the on-disk format is version- and
agent-specific (this installation uses `keyboxd`, which already changed where public keys
live).

```sh
gpg --armor --export-secret-keys <KEY_ID> > zilath-signing-key.asc
```

The **revocation certificate** is the file everyone forgets, and it is the one that decides
what happens on the bad day. With it you can announce that the key is dead even if you no
longer have the key. Without it, a key that is lost or compromised stays valid-looking
forever, and every future signature made with it is indistinguishable from yours.

So: the exported key and the revocation certificate go in **different** places. Whoever
holds the revocation certificate can revoke your key; whoever holds both can revoke it and
sign as you. Encrypted backup for the key, somewhere separate and offline for the
revocation certificate.

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
   `verifier-spring-boot-starter` — each with its jar, sources jar, Dokka javadoc jar, POM,
   signatures and checksums. The demo applications are not published.

   The staging tree is emptied first, automatically. It has to be: it survives between
   builds, so a bundle built on top of it would otherwise carry artifacts from an earlier
   release straight into an upload that cannot be taken back.

5. **Look inside the bundle before uploading.** This is the last moment at which anything is
   reversible.

   ```sh
   unzip -l build/central/zilath-central-bundle.zip
   ```

   ```sh
   BUNDLE=build/central/zilath-central-bundle.zip
   FILES=$(unzip -Z1 "$BUNDLE")

   # 1. Nothing from an earlier release. Set OLD_VERSION to the last one published.
   OLD_VERSION=0.1.0
   printf '%s\n' "$FILES" | grep -c -- "$OLD_VERSION"       # must print 0

   # 2. Every deployable file carries .asc, .md5 and .sha1. Sonatype requires all three,
   #    and this checks whatever is actually in the bundle — jars, poms and .module alike —
   #    rather than the extensions someone remembered to list.
   printf '%s\n' "$FILES" | grep -v '/$' | grep -vE '\.(asc|md5|sha1|sha256|sha512)$' | while read -r f; do
     for ext in asc md5 sha1; do
       printf '%s\n' "$FILES" | grep -qxF "$f.$ext" || echo "MISSING  $f.$ext"
     done
   done                                                      # must print nothing

   # 3. No demo applications, no test fixtures.
   printf '%s\n' "$FILES" | grep -E 'demo-checkout|gate-check|test-fixtures'   # must print nothing
   ```

   The second check is the one that matters: it derives the list of files needing sidecars
   from the bundle itself, so a new artifact type added later is covered without anyone
   remembering to update this file. (`grep -v '/$'` drops the directory entries `unzip -Z1`
   also lists — without it the check reports six missing files that were never files.)

6. **Upload.** Either drop the zip in the Portal's *Publish* page, or use the API with the
   user token from step 2:

   ```sh
   TOKEN_USER=$(security find-generic-password -s zilath-central-user -w)
   TOKEN_PASS=$(security find-generic-password -s zilath-central-pass -w)

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
