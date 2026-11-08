# SplitNut

**Cashu, without trusting a single mint operator to keep the money supply honest.**

A Cashu mint's private keys normally sit with one operator, who can sign unbacked ecash at
will, and no wallet can tell. SplitNut splits every mint key into shares held by *n*
guardians; any *t* of them must cooperate to sign, so the operator alone cannot print money.

* **Wallets see a normal mint.** Standard keysets, token format and NUT-12 DLEQ proofs, so
  cashu.me, Minibits and cdk-cli work unchanged.
* **No mint fork.** Stock `cdk-mintd` already sends all signing to a remote signer over gRPC.
  SplitNut *is* that signer: a coordinator that gathers threshold shares from guardians.
* **Guardians coordinate over Marmot** (MLS over Nostr): an end-to-end encrypted group where
  relays see only ciphertext. Any Nostr relays work; `splitnut-relay` is a local one with a
  wire tap that counts events and flags any plaintext.

Built for [Nut November 2026](https://nutnovember.org). Work in progress.

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
- [ ] Milestone 4: two-round DLEQ, guardian ledger and issuance cap, dashboard
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
cd ../splitnut && CDK_BIN=../cdk/target/release ./scripts/m3.sh
```

`m3.sh` deals a 2-of-3 keyset, gives the coordinator and each guardian a Nostr key, starts a
local relay, three guardian processes, the coordinator and a keyless cdk-mintd, then runs
cdk-cli through mint, send, receive, double spend and melt, kills guardians one by one, and
restarts one. To use public relays instead:
`RELAYS="wss://relay.damus.io wss://nos.lol" CDK_BIN=... ./scripts/m3.sh`.

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

## Threat model (short)

Protected: a compromised mint host (it holds no keys), one rogue or offline guardian below
threshold, and relay operators. Not yet protected: CDK's signer API carries no quote or swap
context, so guardians cannot check that swaps balance or invoices were paid. v1 relies on an
issuance cap and a public ledger. The full write-up comes with milestone 4.

## Licence

MIT. See [LICENSE](LICENSE).
