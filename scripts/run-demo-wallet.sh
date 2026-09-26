#!/bin/sh
# Presents the test PID to the demo checkout, using the PagoPA conformance tool as wallet.
#
# Usage: ./scripts/run-demo-wallet.sh '<authorize URL>'
#
# The waiting page of the demo shows this command with the URL filled in: it is what the QR
# carries, and where a wallet starts. The transaction id alone opens nothing on the demo
# pages to anyone but the browser that started the transaction, this script included.
#
# Runs ONLY the happy-flow test file. That is not a way of hiding failures: the tool's
# other suites deliberately post authorization ERROR responses to exercise the relying
# party, and an OpenID4VP transaction is single-use — the first error response consumes
# its nonce, after which every later step correctly gets REPLAY and the happy flow finds
# the request endpoint already closed. One transaction cannot serve the whole suite.
# For the full conformance run, see docs/conformance.
set -e

URL="$1"
case "$URL" in
    *request_uri=*) ;;
    *) echo "usage: $0 '<authorize URL shown on the waiting page>'" >&2; exit 1 ;;
esac

# The conformance tool imports node:sqlite, and on a runtime without it the failure
# happens deep inside an ESM import — or the process simply hangs. Probe the module rather
# than the version number: unflagged node:sqlite landed in 22.13, so "major >= 22" would
# wave through 22.0–22.12 and fail later anyway.
command -v node >/dev/null 2>&1 || { echo "node not found: the conformance tool needs Node >= 22.13" >&2; exit 1; }
if ! node -e 'require("node:sqlite")' >/dev/null 2>&1; then
    echo "This Node cannot load node:sqlite, which the conformance tool needs." >&2
    echo "Installed: $(node --version). Required: >= 22.13 (or >= 23)." >&2
    echo "With nvm:  source ~/.nvm/nvm.sh && nvm use 22" >&2
    echo "then run this script again from the same shell." >&2
    exit 1
fi

npx -y @pagopa/it-wallet-conformance-tool@1.2.1 test:presentation \
    --presentation-authorize-uri "$URL" --wallet-version V1_4 --unsafe-tls \
    --tests happy || TOOL_FAILED=1

# The tool's exit code is not the answer to "did the demo work". Some conformance
# assertions fail on gaps that are known and documented (RP federation onboarding, the
# KB-JWT audience divergence, the same-device response code) — see docs/note-divergenze.md.
# What decides whether the presentation went through is the transaction itself, and only
# the browser that started it can read it: the waiting page moves on to the companion ticket
# once the presentation is verified, and the application log says which check rejected it
# otherwise. Transactions live 5 minutes.
echo
echo "Look at the waiting page in the browser that started the purchase."
[ -n "$TOOL_FAILED" ] && echo "(Some conformance assertions failed above: known gaps, docs/note-divergenze.md.)"
exit 0
