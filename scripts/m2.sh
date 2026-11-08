#!/usr/bin/env bash
# Milestone 2 end-to-end: stock cdk-mintd with NO keys, signing through splitnut-coord with
# three in-process guardians (2-of-3). cdk-cli mints, sends, receives, is refused a double
# spend, and melts; then one guardian down (still works) and two down (clean refusal).
#
#   CDK_BIN=/path/to/cdk/target/release ./scripts/m2.sh
# CDK_BIN needs cdk-mintd and cdk-cli from CDK v0.18.3 (see scripts/spike.sh).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${CDK_BIN:?set CDK_BIN to the directory holding cdk-mintd and cdk-cli}"
W="${M2_DIR:-$ROOT/.m2}"
MINT=http://127.0.0.1:8085/
SN="$ROOT/target/debug"

(cd "$ROOT" && cargo build -q -p splitnut-dealer -p splitnut-coord)
rm -rf "$W"; mkdir -p "$W/mint"
COORD_PID=""
cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT

"$ROOT/scripts/gen-certs.sh" "$W/certs" >/dev/null
"$SN/splitnut-dealer" -t 2 -n 3 --out "$W/shares" | head -1

start_coord() { # extra args: --offline N ...
  [ -n "$COORD_PID" ] && kill "$COORD_PID" 2>/dev/null && wait "$COORD_PID" 2>/dev/null || true
  "$SN/splitnut-coord" --public "$W/shares/public.json" \
    --local-guardian "$W/shares/guardian-1.json" \
    --local-guardian "$W/shares/guardian-2.json" \
    --local-guardian "$W/shares/guardian-3.json" \
    --tls-dir "$W/certs" "$@" >> "$W/coord.log" 2>&1 &
  COORD_PID=$!
  sleep 1
}

start_coord
sed "s#@CERTS@#$W/certs#; s#@URL@#http://127.0.0.1:8085/#; s#@LISTEN@#127.0.0.1#" "$ROOT/config/mintd.toml" > "$W/mintd.toml"
"$BIN/cdk-mintd" --work-dir "$W/mint" config init --new-mint --file "$W/mintd.toml" > /dev/null
"$BIN/cdk-mintd" --work-dir "$W/mint" > "$W/mint.log" 2>&1 &
for _ in $(seq 30); do curl -sf "${MINT}v1/keysets" >/dev/null && break; sleep 1; done

echo "mint keysets:  $(curl -s "${MINT}v1/keysets" | python3 -c 'import sys,json;print(json.load(sys.stdin)["keysets"][0]["id"])')"
echo "dealer keyset: $(python3 -c 'import json;print(json.load(open("'"$W"'/shares/public.json"))["keyset_id"])')"
grep -q "Rotating keyset" "$W/mint.log" && { echo "FAIL: mint asked for a rotation"; exit 1; }

A=("$BIN/cdk-cli" -n -w "$W/walletA")
B=("$BIN/cdk-cli" -n -w "$W/walletB")

echo "== 2-of-3: mint 1000 into A";  "${A[@]}" mint "$MINT" 1000 | tail -1
TOKEN=$("${A[@]}" send --mint-url "$MINT" -a 400 | grep -o 'cashu[AB][A-Za-z0-9_=-]*' | tail -1)
echo "== B receives 400";            "${B[@]}" receive --allow-untrusted "$TOKEN" | tail -1
echo "== double spend";              "${B[@]}" receive --allow-untrusted "$TOKEN" 2>&1 | tail -1 || true
INVOICE=$(curl -s -X POST "${MINT}v1/mint/quote/bolt11" -H 'content-type: application/json' \
  -d '{"amount":300,"unit":"sat"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["request"])')
echo "== B melts 300";               "${B[@]}" melt --mint-url "$MINT" --invoice "$INVOICE" | tail -1

echo "== guardian 3 down: mint 50 into A"
start_coord --offline 3
"${A[@]}" mint "$MINT" 50 | tail -1

echo "== guardian 1 down (forces signers 2+3): A sends 20 to B"
start_coord --offline 1
TOKEN=$("${A[@]}" send --mint-url "$MINT" -a 20 | grep -o 'cashu[AB][A-Za-z0-9_=-]*' | tail -1)
"${B[@]}" receive --allow-untrusted "$TOKEN" | tail -1

echo "== guardians 2 and 3 down: mint 50 into A (must be refused)"
start_coord --offline 2 --offline 3
if timeout 60 "${A[@]}" mint "$MINT" 50 > "$W/refused.log" 2>&1; then
  echo "FAIL: minted with one guardian"; exit 1
fi
grep -o "quorum unavailable[^\`\"]*" "$W/refused.log" | head -1

echo "A: $("${A[@]}" balance | tail -1)"
echo "B: $("${B[@]}" balance | tail -1)"
echo "== coordinator log (signers per request)"
grep -E "blind_sign ok|verify_proofs ok|quorum|restarting" "$W/coord.log" \
  | sed -E 's/^[^ ]+ +//; s/\x1b\[[0-9;]*m//g' | cut -c1-150
