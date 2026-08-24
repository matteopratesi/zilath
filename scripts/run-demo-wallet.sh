#!/bin/sh
# Presents the test PID to the demo checkout using the PagoPA conformance tool as wallet.
# Usage: ./scripts/run-demo-wallet.sh <transactionId>   (requires Node >= 22)
set -e
TX="$1"
[ -n "$TX" ] || { echo "usage: $0 <transactionId>"; exit 1; }
URL=$(curl -s "http://localhost:8080/demo/authorize-url/$TX")
[ -n "$URL" ] || { echo "transaction not found"; exit 1; }
exec npx -y @pagopa/it-wallet-conformance-tool@1.2.1 test:presentation \
  --presentation-authorize-uri "$URL" --wallet-version V1_4 --unsafe-tls
