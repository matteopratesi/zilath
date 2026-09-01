#!/bin/sh
# Presents the SIMULATED CED to the demo checkout.
# First time: ./scripts/run-ced-wallet.sh init   (then restart the app as instructed)
# Then:       ./scripts/run-ced-wallet.sh <transactionId>
set -e
cd "$(dirname "$0")/.."
if [ "$1" = "init" ]; then
  exec ./gradlew -q :demo-checkout:cedWallet --args="init demo-keys/ced-sim"
fi
[ -n "$1" ] || { echo "usage: $0 init | $0 <transactionId>"; exit 1; }
exec ./gradlew -q :demo-checkout:cedWallet --args="run $1"
