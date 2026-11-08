# SplitNut

**Cashu, without trusting a single mint operator to keep the money supply honest.**

A Cashu mint's private keys normally sit with one operator, who can sign unbacked ecash at
will, and no wallet can tell. SplitNut splits every mint key into shares held by *n*
guardians; any *t* of them must cooperate to sign, so the operator alone cannot print money.

* **Wallets see a normal mint.** Standard keysets, token format and NUT-12 DLEQ proofs. Tested
  with cdk-cli, which verifies every threshold signature's DLEQ; cashu-ts (used by cashu.me)
  checks DLEQs the same way.
* **No mint fork.** Stock `cdk-mintd` already sends all signing to a remote signer over gRPC.
  SplitNut *is* that signer: a coordinator that gathers threshold shares from guardians.
* **Guardians coordinate over Marmot** (MLS over Nostr): an end-to-end encrypted group where
  relays see only ciphertext. Any Nostr relays work; `splitnut-relay` is a local one with a
  wire tap that counts events and flags any plaintext.

Built for [Nut November 2026](https://nutnovember.org). Work in progress.

![SplitNut dashboard: guardians around the mint, live ledgers, what the relay sees, and the request log](docs/dashboard.png)

## Status

- [x] **Milestone 1, spike:** cdk-mintd with no local keys, signing through a remote signer;
      mint, swap and melt with cdk-cli (`scripts/spike.sh`, findings in [docs/spike.md](docs/spike.md))
- [x] **Milestone 2, threshold signing in process:** stock cdk-mintd signs through
      `splitnut-coord` with three guardians, 2-of-3. cdk-cli mints, swaps and melts, and checks
      the DLEQ of every combined signature. One guardian down still works; two down is
      refused with "quorum unavailable" (`scripts/m2.sh`)
- [x] **Milestone 3, guardians over Marmot:** three guardian processes with their own
      Nostr keys and the coordinator form one MLS group over Nostr. Killing a guardian keeps
      the mint working, killing a second makes it refuse, and restarting one resumes signing
      from its encrypted state. The relay sees only ciphertext (`scripts/m3.sh`)
- [x] **Milestone 4, rules and dashboard:** each guardian keeps its own ledger (issuance it
      has verified by DLEQ, redemptions it has checked) and an hourly signing cap; heartbeats
      make quorum loss an immediate, explained refusal; a live dashboard shows each request,
      the guardians, their ledgers and what the relay sees (`scripts/m4.sh`)
- [ ] Milestone 5: demo video, deck, submission

## Architecture

```
wallet ──HTTP──▶ cdk-mintd (unchanged, no keys)
                    │ gRPC (CDK signatory API, mTLS)
                    ▼
              splitnut-coord ──Marmot group──▶ splitnut-guardian × n
              (combines + checks shares,        (one share of every key,
               holds no key material)            rules, ledger)
```

| Crate | Role |
|-------|------|
| `splitnut-core` | Share maths, Lagrange combination, DLEQ round logic |
| `splitnut-proto` | Messages on the Marmot channel |
| `splitnut-dealer` | One-off key generation and t-of-n splitting |
| `splitnut-guardian` | Guardian daemon |
| `splitnut-coord` | Remote signer for cdk-mintd plus Marmot fan-out and dashboard |
| `splitnut-marmot` | Marmot node: MDK + Nostr client in one actor, group setup, encrypted MLS state |
| `splitnut-relay` | Local in-memory relay with a wire tap |

## Run it

```sh
git clone https://github.com/cashubtc/cdk && cd cdk && git checkout v0.18.3
cargo build --release -p cdk-mintd -p cdk-cli   # needs protoc
cd ../splitnut && CDK_BIN=../cdk/target/release ./scripts/m4.sh
```

Open http://127.0.0.1:8090/ while it runs (or run with `KEEP=1` to leave everything up and
mint from your own wallet against `http://127.0.0.1:8085`).

`m4.sh` deals a 2-of-3 keyset, gives the coordinator and each guardian a Nostr key, starts a
local relay, three guardian processes, the coordinator and a keyless cdk-mintd, then runs
cdk-cli through mint, send, receive, double spend and melt, kills guardians one by one,
restarts one, tries to mint over the hourly cap, and checks that every online guardian's
outstanding total equals the wallets' combined balance. To use public relays instead:
`RELAYS="wss://relay.damus.io wss://nos.lol" CDK_BIN=... ./scripts/m4.sh`.

Typical run on a laptop-class machine with a local relay: the group forms in about 4 s; a
two-round threshold signature takes 0.3 to 0.9 s for 1 to 30 outputs, and a proof check
about 0.2 s.

## How the signing works

Each mint key `k` (one per amount) is split t-of-n by the dealer. For a blinded message `B'`
the coordinator runs two rounds with t guardians: each returns `k_i·B'` plus nonce
commitments `r_i·G` and `r_i·B'`, then `s_i = r_i + e·k_i` for the NUT-12 challenge `e`.
Lagrange-combined, this is exactly the signature and DLEQ proof a single-key mint would
produce, so wallets cannot tell the difference. Every share is checked against the
guardian's public share before combining, and a cheating guardian is named and excluded.
Proof checks (`verify_proofs`) work the same way in one round. Details are in
`crates/splitnut-core`.

## Threat model

SplitNut guarantees one thing well: **no single party, the mint operator included, can produce
a valid mint signature without t guardians.**

**Protected**

* *A compromised mint host.* cdk-mintd holds no keys; stealing the server gets no signing power.
* *A rogue or offline guardian, below threshold.* Every share is checked against that guardian's
  public share before combining; a bad share names the guardian, who is excluded while the
  request restarts with fresh nonces. Offline guardians are skipped.
* *Relay operators.* Guardians talk inside an MLS group (Marmot); relays see gift wraps and
  ciphertext only. The bundled relay's wire tap checks this on every event.
* *The coordinator.* It holds no key material and cannot forge signatures. It can refuse service
  or delay requests.

**Rules guardians enforce in v1**

* *Hourly signing cap.* Each guardian refuses to help sign more than its cap per rolling hour,
  checked before both rounds. CDK's signer API carries no context, so the cap counts all
  signing, swaps and change included, not only new money. A coordinator that rotates signer
  sets to spread requests can reach at most `cap × n / t` per hour in total.
* *Independent ledgers.* After each signature the coordinator announces the finished
  signatures to all guardians; each guardian checks every DLEQ against the public mint key
  before counting it, so its *issued* total is issuance it can prove happened. Proof checks go
  to all guardians, and each proof counts as *redeemed* once. `outstanding = issued − redeemed`
  is the ecash in circulation as that guardian sees it, to compare with the mint's Lightning
  balance. In the end-to-end test every online guardian's outstanding equals the wallets'
  combined balance.

**Not protected in v1**

* *Context.* The signer sees blinded messages and proofs separately, with no quote or swap id,
  so guardians cannot check that a swap balances or that a mint quote was paid. Next step: a
  CDK change that passes operation context (inputs with outputs, quote id and payment preimage)
  to the signer, so guardians can enforce "outputs ≤ inputs" and check `sha256(preimage)`
  against the invoice's payment hash.
* *Trusted dealer.* Whoever runs the dealer saw every full key once. Delete its output after
  handing out the share files; distributed key generation is future work.
* *Collusion.* t guardians together can do anything a single operator could. Choose t and n
  accordingly.
* *Liveness.* With fewer than t guardians online the mint stops issuing and redeeming. That is
  the intended failure mode, and it is an immediate, explained refusal rather than a hang.
* *Ledger caveats.* A guardian that was offline misses events, so its totals lag (the dashboard
  says when online guardians disagree). Proofs checked for a swap the mint then rejects still
  count as redeemed. The mint re-checks some proofs (for example during a melt); repeats are
  shown as "checked twice", together with double-spend attempts, rather than blocked. A
  coordinator could withhold an announcement from non-signers; the signers' own signing totals
  still record it.
* *Relay rate limits.* Relays typically accept about one event per second per publisher.
  SplitNut batches identical requests into one message and retries rejected publishes, and the
  test runs under a tighter-than-default limit, but very busy mints would need relays that
  allow more.

## Licence

MIT. See [LICENSE](LICENSE).
