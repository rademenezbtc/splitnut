# Running SplitNut

## What you need

* Rust (stable) and `protoc` (to build CDK).
* `cdk-mintd` and `cdk-cli` from CDK v0.18.3 plus one commit that passes operation context to
  the signer (the mint says what each signature is for, so guardians can check it). It is
  branch `splitnut/operation-context` of https://github.com/rademenezbtc/cdk, the same commit
  SplitNut's `Cargo.toml` patches in:

  ```sh
  git clone https://github.com/rademenezbtc/cdk && cd cdk
  git checkout 702e5bc76b0cfa88b6b3f4ecb5920bfbf7edd4ab   # splitnut/operation-context
  cargo build --release -p cdk-mintd -p cdk-cli
  export CDK_BIN=$PWD/target/release
  ```

  A stock cdk-mintd sends no context, and the guardians refuse it ("no operation context").
  To run against one anyway, with v1's weaker rules (cap every signature, check nothing), start
  the guardians with `--allow-contextless`.

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

## Keys

The guardians generate the keyset themselves (distributed key generation, `docs/dkg.md`);
`demo.sh` and `m4.sh` do this on a fresh start. By hand, with a relay up and a roster file
(index → npub) that every guardian and the coordinator hold:

```sh
splitnut-guardian dkg --keys g1.nsec --roster roster.json --coordinator npub1... \
    --relay ws://127.0.0.1:7777 --out guardian-1.json          # on each guardian
splitnut-coord --dkg -t 2 --roster roster.json --keys coord.nsec \
    --relay ws://127.0.0.1:7777 --public shares/public.json   # once, on the coordinator
```

Each guardian writes its own share file and exits; the coordinator writes `public.json` once
every guardian has confirmed the same keyset. Then start them normally (`run`); they resume
the same Marmot group. `KEYGEN=dealer` makes the scripts use the trusted dealer instead.

## The tests

| Script | What it shows |
|--------|---------------|
| `scripts/spike.sh` | cdk-mintd with no keys, signing through CDK's reference remote signer |
| `scripts/m2.sh` | 2-of-3 threshold signing with in-process guardians |
| `scripts/m3.sh` | guardians as separate processes over Marmot; kill one, kill two, restart one |
| `scripts/m4.sh` | plus ledgers, the hourly cap, fast refusal and the dashboard; checks that each guardian's outstanding total equals the wallets' balance; then attacks the guardians as a compromised mint host (`examples/evil_mintd.rs`) and checks each attack is refused; restarts a guardian that missed most of the run and checks it catches up exactly; audits the public ledgers |

`cargo test --workspace` runs the unit and integration tests (threshold maths against the
`cashu` crate's own checks, the coordinator with cheating and offline guardians, a Marmot
group on an in-process relay, and the guardian rules: unbalanced swaps, forged or thin input
evidence, double spends across swaps and melts, over-issuing against a quote).

To attack a running demo yourself: `cargo run -p splitnut-coord --example evil_mintd -- --tls-dir .demo/certs`.

To audit a running demo from the outside (the guardians' signed public ledgers):
`cargo run -p splitnut-coord --example audit -- --roster .demo/roster.json --relay ws://127.0.0.1:7777`.
Guardians publish every 30 s (`--publish-secs`).
