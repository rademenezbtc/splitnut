#!/usr/bin/env bash
# Milestone 3 end-to-end: guardians as separate processes over Marmot.
#
# Starts a local relay (or uses RELAYS), three guardian processes with their own Nostr keys,
# the coordinator in Marmot mode, and stock cdk-mintd with no keys. cdk-cli then mints,
# sends, receives, is refused a double spend and melts; guardian 1 is killed (signers become
# 2+3), then guardian 2 (the mint refuses), then guardian 2 is restarted (signing resumes
# from its encrypted MLS state, no new setup).
#
#   CDK_BIN=/path/to/cdk/target/release ./scripts/m3.sh
#   RELAYS="wss://relay.damus.io wss://nos.lol" CDK_BIN=... ./scripts/m3.sh   # public relays
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${CDK_BIN:?set CDK_BIN to the directory holding cdk-mintd and cdk-cli}"
W="${M3_DIR:-$ROOT/.m3}"
MINT=http://127.0.0.1:8085/
SN="$ROOT/target/debug"
RELAYS="${RELAYS:-ws://127.0.0.1:7777}"
RELAY_ARGS=(); for r in $RELAYS; do RELAY_ARGS+=(--relay "$r"); done

(cd "$ROOT" && cargo build -q -p splitnut-dealer -p splitnut-coord -p splitnut-guardian -p splitnut-relay)
rm -rf "$W"; mkdir -p "$W/mint" "$W/keys" "$W/logs"
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT

declare -A GPID
start_guardian() {
  local i=$1
  "$SN/splitnut-guardian" run --share "$W/shares/guardian-$i.json" --keys "$W/keys/g$i.nsec" \
    --coordinator "$COORD_NPUB" "${RELAY_ARGS[@]}" >> "$W/logs/guardian-$i.log" 2>&1 &
  GPID[$i]=$!
}
wait_log() { # file pattern seconds
  for _ in $(seq $(( $3 * 4 ))); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 0.25; done
  echo "timed out waiting for '$2' in $1"; return 1
}

# ---- setup: certs, keyset, identities, roster ----
"$ROOT/scripts/gen-certs.sh" "$W/certs" >/dev/null
"$SN/splitnut-dealer" -t 2 -n 3 --out "$W/shares" | head -1
COORD_NPUB=$("$SN/splitnut-coord" --keygen --keys "$W/keys/coord.nsec")
{
  echo '{"guardians":['
  for i in 1 2 3; do
    npub=$("$SN/splitnut-guardian" keygen --keys "$W/keys/g$i.nsec")
    echo "  {\"index\":$i,\"npub\":\"$npub\"}$([ $i -lt 3 ] && echo ,)"
  done
  echo ']}'
} > "$W/roster.json"
echo "coordinator $COORD_NPUB; roster:"; grep -o 'npub1[a-z0-9]*' "$W/roster.json" | sed 's/^/  /'

# ---- processes ----
if [ "$RELAYS" = "ws://127.0.0.1:7777" ]; then
  "$SN/splitnut-relay" --port 7777 --report-secs 2 > "$W/logs/relay.log" 2>&1 &
  wait_log "$W/logs/relay.log" "relay listening" 10
fi
for i in 1 2 3; do start_guardian $i; done
"$SN/splitnut-coord" --public "$W/shares/public.json" --roster "$W/roster.json" "${RELAY_ARGS[@]}" \
  --keys "$W/keys/coord.nsec" --tls-dir "$W/certs" > "$W/logs/coord.log" 2>&1 &
T0=$(date +%s.%N)
wait_log "$W/logs/coord.log" "guardian group ready" 120
for i in 1 2 3; do wait_log "$W/logs/guardian-$i.log" "joined the guardian group" 60; done
echo "Marmot group formed in $(printf %.1f "$(echo "$(date +%s.%N) - $T0" | bc)") s (coordinator + 3 guardians)"

sed "s#@CERTS@#$W/certs#; s#@URL@#http://127.0.0.1:8085/#; s#@LISTEN@#127.0.0.1#" "$ROOT/config/mintd.toml" > "$W/mintd.toml"
"$BIN/cdk-mintd" --work-dir "$W/mint" config init --new-mint --file "$W/mintd.toml" > /dev/null
"$BIN/cdk-mintd" --work-dir "$W/mint" > "$W/logs/mint.log" 2>&1 &
for _ in $(seq 30); do curl -sf "${MINT}v1/keysets" >/dev/null && break; sleep 1; done
grep -q "Rotating keyset" "$W/logs/mint.log" && { echo "FAIL: mint asked for a rotation"; exit 1; }

A=("$BIN/cdk-cli" -n -w "$W/walletA")
B=("$BIN/cdk-cli" -n -w "$W/walletB")
timed() { local s; s=$(date +%s.%N); "$@"; echo "   ($(printf %.2f "$(echo "$(date +%s.%N) - $s" | bc)") s)"; }

echo "== all 3 guardians: mint 1000 into A"; timed "${A[@]}" mint "$MINT" 1000 | tail -1
TOKEN=$("${A[@]}" send --mint-url "$MINT" -a 400 | grep -o 'cashu[AB][A-Za-z0-9_=-]*' | tail -1)
echo "== B receives 400";                   timed "${B[@]}" receive --allow-untrusted "$TOKEN" | tail -1
echo "== double spend";                     "${B[@]}" receive --allow-untrusted "$TOKEN" 2>&1 | tail -1 || true
INVOICE=$(curl -s -X POST "${MINT}v1/mint/quote/bolt11" -H 'content-type: application/json' \
  -d '{"amount":300,"unit":"sat"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["request"])')
echo "== B melts 300";                      timed "${B[@]}" melt --mint-url "$MINT" --invoice "$INVOICE" | tail -1

echo "== kill guardian 1 (pid ${GPID[1]}): A sends 20 to B"
kill "${GPID[1]}"; wait "${GPID[1]}" 2>/dev/null || true
TOKEN=$("${A[@]}" send --mint-url "$MINT" -a 20 | grep -o 'cashu[AB][A-Za-z0-9_=-]*' | tail -1)
timed "${B[@]}" receive --allow-untrusted "$TOKEN" | tail -1

echo "== kill guardian 2 (pid ${GPID[2]}): mint 50 into A (must be refused)"
kill "${GPID[2]}"; wait "${GPID[2]}" 2>/dev/null || true
if timeout 60 "${A[@]}" mint "$MINT" 50 > "$W/logs/refused.log" 2>&1; then echo "FAIL: minted with one guardian"; exit 1; fi
grep -o "quorum unavailable[^\`\"]*" "$W/logs/refused.log" | head -1

echo "== restart guardian 2: it resumes the group from its encrypted state; mint 50 into A"
start_guardian 2
wait_log "$W/logs/guardian-2.log" "resumed existing group" 30
sleep 1
timed "${A[@]}" mint "$MINT" 50 | tail -1

echo "A: $("${A[@]}" balance | tail -1)"
echo "B: $("${B[@]}" balance | tail -1)"
echo "== coordinator: signers and latency per request"
grep -E "blind_sign ok|verify_proofs ok|quorum unavailable: refusing" "$W/logs/coord.log" \
  | sed -E 's/\x1b\[[0-9;]*m//g; s/^.*signer: //' | cut -c1-120
if [ -f "$W/logs/relay.log" ]; then
  sleep 2.5
  echo "== relay wire tap"
  grep "wire tap" "$W/logs/relay.log" | tail -1 | sed -E 's/\x1b\[[0-9;]*m//g; s/^.*wire tap: //' | tr '|' '\n' | sed 's/^ */  /'
  grep -q "plaintext marker seen" "$W/logs/relay.log" && { echo "FAIL: plaintext on the relay"; exit 1; } || true
fi
