#!/usr/bin/env bash
# One command for the whole SplitNut demo: a relay (local unless RELAYS is set), three
# guardians, the coordinator with its dashboard, and cdk-mintd with no keys. On the first run
# the guardians generate the keyset among themselves (distributed key generation; nobody ever
# holds a whole key). KEYGEN=dealer uses the trusted dealer instead.
# Ctrl+C stops everything. State is kept in $DEMO_DIR, so running it again resumes the same
# keyset, Marmot group, ledgers and mint database; pass --fresh to start over.
#
#   CDK_BIN=/path/to/cdk/target/release ./scripts/demo.sh            # local relay
#   RELAYS="wss://relay.damus.io wss://nos.lol" CDK_BIN=... ./scripts/demo.sh
#   MINT_URL=https://my-tunnel.example LISTEN=0.0.0.0 CDK_BIN=... ./scripts/demo.sh
#
# While it runs:  ./scripts/guardian.sh stop 3   /   ./scripts/guardian.sh start 3
#
# Settings (environment): T, N (2, 3), CAP sat/hour per guardian (100000), MINT_URL
# (http://127.0.0.1:8085/), LISTEN (127.0.0.1), DASHBOARD (127.0.0.1:8090), PROFILE
# (release|debug), HEARTBEAT seconds (3; use 10 or more on public relays), DEMO_DIR (.demo),
# KEYGEN (dkg|dealer). cdk-mintd must include operation context (docs/RUNNING.md).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${CDK_BIN:?set CDK_BIN to the directory holding cdk-mintd and cdk-cli (CDK v0.18.3 + operation context)}"
KEYGEN="${KEYGEN:-dkg}"
W="${DEMO_DIR:-$ROOT/.demo}"
T="${T:-2}"; N="${N:-3}"; CAP="${CAP:-100000}"
MINT_URL="${MINT_URL:-http://127.0.0.1:8085/}"
LISTEN="${LISTEN:-127.0.0.1}"
DASHBOARD="${DASHBOARD:-127.0.0.1:8090}"
PROFILE="${PROFILE:-release}"
LOCAL_RELAY=""
if [ -z "${RELAYS:-}" ]; then RELAYS="ws://127.0.0.1:7777"; LOCAL_RELAY=1; fi

[ "${1:-}" = "--fresh" ] && rm -rf "$W"
mkdir -p "$W/logs" "$W/pids" "$W/keys" "$W/mint"
# Each run starts with fresh logs (the previous run's are kept in logs/previous/), so the
# readiness checks below only ever see this run's output.
if ls "$W"/logs/*.log >/dev/null 2>&1; then
  rm -rf "$W/logs/previous"; mkdir -p "$W/logs/previous"; mv "$W"/logs/*.log "$W/logs/previous/"
fi

echo "building ($PROFILE)..."
FLAG=""; [ "$PROFILE" = release ] && FLAG="--release"
(cd "$ROOT" && cargo build -q $FLAG -p splitnut-dealer -p splitnut-coord -p splitnut-guardian -p splitnut-relay \
  && cargo build -q $FLAG -p splitnut-coord --example evil_mintd)
SN="$ROOT/target/$PROFILE"
echo "$SN" > "$W/bin"

RELAY_ARGS=(); for r in $RELAYS; do RELAY_ARGS+=(--relay "$r"); done

# ---- one-time setup ----
if [ ! -f "$W/roster.json" ]; then
  echo "first run: creating identities"
  "$ROOT/scripts/gen-certs.sh" "$W/certs" >/dev/null
  mkdir -p "$W/shares"
  "$SN/splitnut-coord" --keygen --keys "$W/keys/coord.nsec" > "$W/coord.npub"
  {
    echo '{"guardians":['
    for i in $(seq 1 "$N"); do
      npub=$("$SN/splitnut-guardian" keygen --keys "$W/keys/g$i.nsec")
      echo "  {\"index\":$i,\"npub\":\"$npub\"}$([ "$i" -lt "$N" ] && echo ,)"
    done
    echo ']}'
  } > "$W/roster.json"
fi
COORD_NPUB=$(cat "$W/coord.npub")

# ---- processes ----
PIDS=()
cleanup() {
  echo; echo "stopping..."
  for f in "$W"/pids/*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null || true; rm -f "$f"; done
  kill "${PIDS[@]}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait_log() { for _ in $(seq $(( $3 * 4 ))); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 0.25; done; echo "timed out waiting for '$2' in $1" >&2; return 1; }

if [ -n "$LOCAL_RELAY" ]; then
  "$SN/splitnut-relay" --port 7777 --http-port 7778 > "$W/logs/relay.log" 2>&1 &
  echo $! > "$W/pids/relay.pid"
  wait_log "$W/logs/relay.log" "relay listening" 10
  TAP=(--relay-tap-url http://127.0.0.1:7778/stats)
  # The local relay is in memory: a restart forgets the group's history, so start the
  # Marmot side fresh (keys, keyset, ledgers and the mint stay).
  rm -f "$W"/keys/*.mls.sqlite*
else
  TAP=()
fi

if [ ! -f "$W/shares/public.json" ]; then
  if [ "$KEYGEN" = dealer ]; then
    echo "dealing a $T-of-$N keyset (trusted dealer)"
    "$SN/splitnut-dealer" -t "$T" -n "$N" --out "$W/shares" --force | head -1
  else
    echo "distributed key generation: $N guardians, threshold $T (nobody holds a whole key)..."
    rm -f "$W"/shares/guardian-*.json
    DKG_PIDS=()
    for i in $(seq 1 "$N"); do
      "$SN/splitnut-guardian" dkg --keys "$W/keys/g$i.nsec" --roster "$W/roster.json" --coordinator "$COORD_NPUB" \
        "${RELAY_ARGS[@]}" --out "$W/shares/guardian-$i.json" > "$W/logs/dkg-guardian-$i.log" 2>&1 &
      DKG_PIDS+=($!)
    done
    "$SN/splitnut-coord" --dkg -t "$T" --roster "$W/roster.json" "${RELAY_ARGS[@]}" --keys "$W/keys/coord.nsec" \
      --public "$W/shares/public.json" > "$W/logs/dkg-coord.log" 2>&1 \
      || { tail -5 "$W/logs/dkg-coord.log"; echo "key generation failed"; exit 1; }
    for p in "${DKG_PIDS[@]}"; do wait "$p" || { echo "a guardian's key generation failed (see $W/logs)"; exit 1; }; done
    grep "^keyset" "$W/logs/dkg-coord.log"
  fi
fi

# Guardian command lines are saved so scripts/guardian.sh can stop and start them.
for i in $(seq 1 "$N"); do
  {
    printf '%q ' "$SN/splitnut-guardian" run --share "$W/shares/guardian-$i.json" --keys "$W/keys/g$i.nsec" \
      --coordinator "$COORD_NPUB" "${RELAY_ARGS[@]}" --cap-per-hour "$CAP"
    echo
  } > "$W/guardian-$i.cmd"
  bash -c "exec $(cat "$W/guardian-$i.cmd")" >> "$W/logs/guardian-$i.log" 2>&1 &
  echo $! > "$W/pids/guardian-$i.pid"
done

"$SN/splitnut-coord" --public "$W/shares/public.json" --roster "$W/roster.json" "${RELAY_ARGS[@]}" \
  --keys "$W/keys/coord.nsec" --tls-dir "$W/certs" --dashboard "$DASHBOARD" "${TAP[@]}" \
  --heartbeat-secs "${HEARTBEAT:-3}" >> "$W/logs/coord.log" 2>&1 &
echo $! > "$W/pids/coord.pid"
echo "waiting for the guardian group..."
wait_log "$W/logs/coord.log" "guardian group ready" 180

if [ ! -f "$W/mint/.initialised" ]; then
  sed "s#@CERTS@#$W/certs#; s#@URL@#$MINT_URL#; s#@LISTEN@#$LISTEN#" "$ROOT/config/mintd.toml" > "$W/mintd.toml"
  "$BIN/cdk-mintd" --work-dir "$W/mint" config init --new-mint --file "$W/mintd.toml" > /dev/null
  touch "$W/mint/.initialised"
fi
"$BIN/cdk-mintd" --work-dir "$W/mint" >> "$W/logs/mint.log" 2>&1 &
echo $! > "$W/pids/mint.pid"
for _ in $(seq 30); do curl -sf "http://127.0.0.1:8085/v1/keysets" >/dev/null && break; sleep 1; done

cat <<EOF

  SplitNut is running ($T of $N guardians must sign).
    Mint       $MINT_URL   (add it to any Cashu wallet)
    Dashboard  http://$DASHBOARD/
    Relays     $RELAYS
    Logs       $W/logs/

  Try:  $BIN/cdk-cli -w $W/wallet mint $MINT_URL 1000
        ./scripts/guardian.sh stop 3     ./scripts/guardian.sh start 3

  Ctrl+C stops everything.
EOF
wait
