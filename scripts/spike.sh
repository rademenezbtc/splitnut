#!/usr/bin/env bash
# Milestone 1 spike: cdk-mintd with NO local keys, signing through CDK's reference remote
# signatory over mTLS gRPC; cdk-cli mints, sends, receives, rejects a double spend, and melts.
#
# Needs CDK v0.18.3 binaries: cdk-mintd, signatory, cdk-cli. Point CDK_BIN at their directory:
#   git clone https://github.com/cashubtc/cdk && cd cdk && git checkout v0.18.3
#   cargo build --release -p cdk-mintd -p cdk-signatory -p cdk-cli
#   CDK_BIN=$PWD/target/release ./scripts/spike.sh
# (Building needs protoc on PATH or PROTOC set.)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${CDK_BIN:?set CDK_BIN to the directory holding cdk-mintd, signatory and cdk-cli}"
W="${SPIKE_DIR:-$ROOT/.spike}"
MINT=http://127.0.0.1:8085/

rm -rf "$W"; mkdir -p "$W"/{signer,mint}
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT

"$ROOT/scripts/gen-certs.sh" "$W/certs" >/dev/null
sed "s#@CERTS@#$W/certs#; s#@URL@#http://127.0.0.1:8085/#; s#@LISTEN@#127.0.0.1#" "$ROOT/config/mintd.toml" > "$W/mintd.toml"

"$BIN/signatory" --work-dir "$W/signer" --certs "$W/certs" --enable-logging --log-level info > "$W/signer.log" 2>&1 &
sleep 2
"$BIN/cdk-mintd" --work-dir "$W/mint" config init --new-mint --file "$W/mintd.toml" > /dev/null
"$BIN/cdk-mintd" --work-dir "$W/mint" > "$W/mint.log" 2>&1 &
for _ in $(seq 30); do curl -sf "${MINT}v1/keysets" >/dev/null && break; sleep 1; done
echo "keysets: $(curl -s "${MINT}v1/keysets")"

A=("$BIN/cdk-cli" -n -w "$W/walletA")
B=("$BIN/cdk-cli" -n -w "$W/walletB")

echo "== mint 1000 into A";  "${A[@]}" mint "$MINT" 1000 | tail -1
TOKEN=$("${A[@]}" send --mint-url "$MINT" -a 400 | grep -o 'cashu[AB][A-Za-z0-9_=-]*' | tail -1)
echo "== B receives 400";    "${B[@]}" receive --allow-untrusted "$TOKEN" | tail -1
echo "== double spend";      "${B[@]}" receive --allow-untrusted "$TOKEN" 2>&1 | tail -1 || true
INVOICE=$(curl -s -X POST "${MINT}v1/mint/quote/bolt11" -H 'content-type: application/json' \
  -d '{"amount":300,"unit":"sat"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["request"])')
echo "== B melts 300";       "${B[@]}" melt --mint-url "$MINT" --invoice "$INVOICE" | tail -1
echo "A: $("${A[@]}" balance | tail -1)"
echo "B: $("${B[@]}" balance | tail -1)"
