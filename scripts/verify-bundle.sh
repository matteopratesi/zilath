#!/bin/bash
#
# Checks a Maven Central bundle before it is uploaded — the last moment at which anything
# about a release is still reversible.
#
# This is a script and not a paragraph of commands in docs/releasing.md because a check
# that only prints its findings is a check that gets ignored. This one exits non-zero.
#
#   usage: scripts/verify-bundle.sh <version> [bundle.zip]
#
set -euo pipefail

VERSION="${1:-}"
BUNDLE="${2:-build/central/zilath-central-bundle.zip}"

if [ -z "$VERSION" ]; then
    echo "usage: $0 <version> [bundle.zip]" >&2
    echo "  e.g. $0 0.2.0" >&2
    exit 2
fi
[ -f "$BUNDLE" ] || { echo "no bundle at $BUNDLE — run ./gradlew centralBundle first" >&2; exit 2; }

FILES=$(unzip -Z1 "$BUNDLE")
DEPLOYABLE=$(printf '%s\n' "$FILES" | grep -v '/$' | grep -vE '\.(asc|md5|sha1|sha256|sha512)$' || true)
problems=0

note() { printf '  %s\n' "$1"; problems=$((problems + 1)); }

echo "Bundle: $BUNDLE"
echo "Expected version: $VERSION"
echo

# 1. Every deployable file belongs to the version being released. Asserting the expected
#    version POSITIVELY, rather than excluding one known-old one, is what catches the
#    version nobody thought to exclude.
echo "1. every artifact belongs to $VERSION"
while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$(basename "$f")" in
        *"$VERSION"*) ;;
        *) note "unexpected version: $f" ;;
    esac
done <<EOF
$DEPLOYABLE
EOF

# 2. Signature and both checksums for every deployable file. Derived from the bundle, so a
#    new artifact type is covered without anyone remembering to update this script.
echo "2. .asc, .md5 and .sha1 for every artifact"
while IFS= read -r f; do
    [ -n "$f" ] || continue
    for ext in asc md5 sha1; do
        printf '%s\n' "$FILES" | grep -qxF "$f.$ext" || note "missing: $f.$ext"
    done
done <<EOF
$DEPLOYABLE
EOF

# 3. Nothing that was never meant to be published.
echo "3. no demo applications, no test fixtures"
while IFS= read -r f; do
    [ -n "$f" ] || continue
    note "must not be published: $f"
done <<EOF
$(printf '%s\n' "$FILES" | grep -E 'demo-checkout|test-fixtures' || true)
EOF

echo
COUNT=$(printf '%s\n' "$DEPLOYABLE" | grep -c . || true)

# A bundle with no artifacts passes every check above, because there is nothing for them
# to fail on. It is the quietest way a verification can say yes.
[ "$COUNT" -gt 0 ] || note "the bundle contains no deployable artifact at all"

if [ "$problems" -eq 0 ]; then
    echo "OK — $COUNT artifacts, all of $VERSION, all signed and checksummed."
    exit 0
fi
echo "$problems problem(s). Do not upload: nothing above is fixable after the fact."
exit 1
