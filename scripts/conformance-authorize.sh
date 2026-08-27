#!/usr/bin/env bash
# Prints the authorize URL of a fresh transaction, for the PagoPA conformance tool's
# `[presentation] authorize_request_script` (it reads exactly one URL from stdout).
set -euo pipefail
BASE_URL="${VARCO_DEMO_BASE_URL:-http://localhost:8080}"
curl -sS "${BASE_URL}/conformance/start" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["authorizeUrl"])'
