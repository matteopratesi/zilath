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
gpg --batch --gen-key scripts/gpg-release-key.params   # prompts for the passphrase, and only that
gpg --list-secret-keys --keyid-format=long     # note the key id and the fingerprint
gpg --send-keys --keyserver keys.openpgp.org <KEY_ID>
```

RSA 4096, sign-only, three years. RSA rather than Ed25519 because what matters here is that
the signature verifies in whatever tool meets the artifact, forever; expiry is safe because
signatures made while the key was valid stay valid, and an expired key fails the bundle
*before* an upload rather than after.

The user id goes on a public keyserver and stays there. Decide the name and email before
generating, not after.

Store **only the passphrase** in the keychain:

```sh
security add-generic-password -a "$USER" -s zilath-signing-pass -w
```

The key itself does not go in the keychain. It is already on this machine, in the GnuPG
keyring, protected by that passphrase — copying it into a second store would mean two
things to guard, two things to rotate and two things to leak, for no gain. The release step
exports it into an environment variable that lives for one shell.

Note that `gpg --armor --export-secret-keys` emits the key **still protected by the
passphrase**: that is why the build needs both `ZILATH_SIGNING_KEY` and
`ZILATH_SIGNING_PASSWORD`, and why the exported blob on its own is not enough to sign with.

**Never** put the key in the repo, in an environment file, or in a CI variable that prints
on failure.

#### Back up two files, in two different places

```text
~/.gnupg/private-keys-v1.d/          the private key material
~/.gnupg/openpgp-revocs.d/<FP>.rev   the revocation certificate, created automatically
```

Do not back up those directories by copying them. Export instead — an export is one
self-contained file that restores on any machine, while the on-disk format is version- and
agent-specific (this installation uses `keyboxd`, which already changed where public keys
live).

```sh
umask 077
gpg --armor --export-secret-keys <FINGERPRINT> > /Volumes/<encrypted-media>/zilath-signing-key.asc
```

Write it straight to the encrypted medium, never into this checkout and never into your
home directory "for a second". A secret key sitting in a git working tree is how secret
keys end up in commits. `scripts/../backup-signing-key.sh` in the working notes does this
plus a restore test; the point either way is that the file is never in a directory git
watches.

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
   export ZILATH_SIGNING_KEY="$(gpg --armor --export-secret-keys <FINGERPRINT>)"
   export ZILATH_SIGNING_PASSWORD="$(security find-generic-password -a "$USER" -s zilath-signing-pass -w)"
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
   ./scripts/verify-bundle.sh 0.2.0     # the version you are releasing
   ```

   It checks three things and **exits non-zero** if any fails, because a check that only
   prints its findings is one that eventually gets scrolled past:

   - every artifact belongs to the version being released — asserted positively against the
     expected version, not by excluding one old version somebody remembered;
   - every artifact has its `.asc`, `.md5` and `.sha1`, derived from the bundle itself so a
     new artifact type is covered without editing the script;
   - nothing from `demo-checkout` or the test fixtures got in.

   On a bundle that is fine it prints one line. On a bundle that is not, it prints what is
   wrong and refuses — and nothing it reports is fixable after an upload. To eyeball the
   contents yourself as well: `unzip -l build/central/zilath-central-bundle.zip`.

6. **Upload.** Either drop the zip in the Portal's *Publish* page, or use the API with the
   user token from step 2:

   ```sh
   TOKEN_USER=$(security find-generic-password -a "$USER" -s zilath-central-user -w)
   TOKEN_PASS=$(security find-generic-password -a "$USER" -s zilath-central-pass -w)

   DEPLOYMENT_ID=$(curl -sS --fail-with-body -X POST \
     https://central.sonatype.com/api/v1/publisher/upload \
     -H "Authorization: Bearer $(printf '%s:%s' "$TOKEN_USER" "$TOKEN_PASS" | base64)" \
     -F bundle=@build/central/zilath-central-bundle.zip)

   [ -n "$DEPLOYMENT_ID" ] || { echo "upload failed: no deployment id" >&2; exit 1; }
   echo "$DEPLOYMENT_ID"
   ```

   `--fail-with-body` matters: without it `curl` exits 0 on an HTTP 401 or 500 and prints
   the error into your variable, so a failed upload looks like a successful one until you
   go looking for a release that was never staged.

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
| `demo-checkout` | no — an application, not an artifact to depend on |

The test fixtures of `verifier-core` are deliberately excluded: they were written for our own
tests, not as a supported API, and publishing them would commit us to keeping them stable
forever. Adding them later is easy; removing them later is impossible.

## Before the first release

Nothing outstanding as of 2026-09-01. Both blockers that stood here are closed:

- the repository is public since 2026-08-30, so the POM `url` and `scm` resolve;
- the unverified status list signature is fixed — the token is validated before it is
  believed.

What remains is not a blocker but worth reading once: **the API is not frozen**. Publishing
`0.2.0` puts these coordinates in front of people permanently, and a `0.x` line is the
promise that they may still move. Say so in the release notes rather than letting somebody
infer stability from the mere fact of a Central release.
