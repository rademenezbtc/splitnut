# Running SplitNut

## What you need

* Rust (stable) and `protoc` (to build CDK).
* CDK v0.18.3's `cdk-mintd` and `cdk-cli`:

  ```sh
  git clone https://github.com/cashubtc/cdk && cd cdk && git checkout v0.18.3
  cargo build --release -p cdk-mintd -p cdk-cli
  export CDK_BIN=$PWD/target/release
  ```

  If cdk-mintd later fails with a bare "transport error", your OpenSSL is older than 3.2 and
  CDK's own certificate script made a v1 client certificate. SplitNut's `scripts/gen-certs.sh`
  (used by every script here) avoids that.

## The demo, one command

```sh
./scripts/demo.sh
```

This starts a local relay, three guardians, the coordinator with its dashboard, and cdk-mintd
with no keys. When it says "SplitNut is running":

* add `http://127.0.0.1:8085/` to a wallet, or use
  `$CDK_BIN/cdk-cli -w .demo/wallet mint http://127.0.0.1:8085/ 1000`;
* open the dashboard at http://127.0.0.1:8090/;
* stop and start guardians with `./scripts/guardian.sh stop 3`, `./scripts/guardian.sh start 3`,
  `./scripts/guardian.sh status`.

Ctrl+C stops everything. Running it again resumes the same keyset, ledgers and mint (your
ecash stays valid); `./scripts/demo.sh --fresh` starts over. Settings are environment
variables, listed at the top of the script (threshold, cap, ports, heartbeat).

## Public relays

```sh
RELAYS="wss://relay.damus.io wss://nos.lol wss://relay.primal.net" HEARTBEAT=10 ./scripts/demo.sh
```

* Use two or three relays: a message counts as sent when any one of them accepts it.
* The relays must accept Marmot's event kinds: key packages (443 and 30443), gift-wrapped
  welcomes (1059) and group messages (445). Most general-purpose relays do.
* Relays rate-limit publishers, often to about one event per second. SplitNut batches identical
  requests into one message and retries rejected ones; the end-to-end test passes at 60 events
  per minute. Keep the heartbeat at 10 seconds or more on public relays. The trade-off: after a
  guardian dies it can take up to one heartbeat (plus the request timeout) before the mint
  refuses straight away, rather than after a short wait.
* Relays keep history, so restarting the demo resumes the same Marmot group. With the local
  relay (in memory) a restart builds a new group automatically.
* The dashboard's "What the relay sees" panel needs the local relay's wire tap. With public
  relays that panel is empty; everything else works.

## Phone wallets

The mint has to be reachable from the phone.

* **Same Wi-Fi:** `LISTEN=0.0.0.0 MINT_URL=http://<your-laptop-LAN-ip>:8085/ ./scripts/demo.sh --fresh`
  and add that URL in the wallet. Native apps may accept a plain-http mint on a LAN; check yours.
* **cashu.me** is served over HTTPS, so browsers block it from talking to a plain-http mint. Put
  the mint behind an HTTPS tunnel, for example `cloudflared tunnel --url http://localhost:8085`,
  and start the demo with `MINT_URL=https://<the-tunnel-host>/`.

`MINT_URL` is written into the mint's config on its first run, hence `--fresh` when you change
it. Wallets that check DLEQ proofs (cdk-cli, cashu-ts, so cashu.me) verify every threshold
signature against the mint's published keys, exactly as for a single-key mint.

## The tests

| Script | What it shows |
|--------|---------------|
| `scripts/spike.sh` | cdk-mintd with no keys, signing through CDK's reference remote signer |
| `scripts/m2.sh` | 2-of-3 threshold signing with in-process guardians |
| `scripts/m3.sh` | guardians as separate processes over Marmot; kill one, kill two, restart one |
| `scripts/m4.sh` | plus ledgers, the hourly cap, fast refusal and the dashboard; checks that each guardian's outstanding total equals the wallets' balance |

`cargo test --workspace` runs the unit and integration tests (threshold maths against the
`cashu` crate's own checks, the coordinator with cheating and offline guardians, a Marmot
group on an in-process relay).
