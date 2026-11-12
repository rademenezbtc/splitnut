# Operation context: guardians that check what they sign

## The problem

In v1 the guardians were blind. CDK's signer API passes blinded messages to `blind_sign` and
proofs to `verify_proofs`, with nothing linking them: no quote, no swap, no inputs. So the
guardians signed whatever the mint host sent, up to an hourly cap. Splitting the key stopped
key theft, but whoever controlled the mint host could still issue unbacked ecash within the cap.

## The change to CDK

One commit on CDK v0.18.3 (branch `splitnut/operation-context` of
[rademenezbtc/cdk](https://github.com/rademenezbtc/cdk)), backwards compatible both ways:

* The `Signatory` trait gains `blind_sign_with_context` and `verify_proofs_with_context`. Both
  take an `Option<OperationContext>`, and their defaults ignore it and call the old methods, so
  existing signatories don't change.
* The gRPC messages `BlindedMessages` and `Proofs` gain an optional `context` field. Older
  servers ignore it, and older clients don't send it.
* The mint fills it in at each call site:

| Call | Context |
|------|---------|
| Issuing for paid mint quotes | `Mint { quotes: [{ id, amount_paid, amount_issued, request }] }` |
| Swap: checking inputs | `Swap { inputs: [] }` (the proofs being checked are the inputs) |
| Swap: signing outputs | `Swap { inputs }` |
| Melt: checking inputs | `Melt { quote_id, amount, request, inputs: [] }` |
| Melt: signing change | `Melt { quote_id, amount, request, inputs }` |

CDK's own swap, melt, issue and verification tests (181) pass with the change.

## What the guardians check

A guardian's round-1 answer already contains its share of each signature (`k_i·B'`), so every
check, and every ledger entry, happens before round 1. Violations are answered with
`refused: …`, which the coordinator reports as a refusal rather than as an outage.

**Inputs carry evidence.** For every input of a swap or melt, the coordinator attaches the
partial evaluations `Y_i = k_i·Y` of t guardians, each with its DLEQ proof against that
guardian's public share. These are the answers from the proof check cdk-mintd ran a moment
earlier for the same operation, which the coordinator caches; if none are cached it runs a
check itself. Each guardian checks every DLEQ and that the partials combine to the proof's `C`.
It therefore knows the input is validly signed without trusting the coordinator or the host.

**Swap** (operation id: hash of its input `Y`s)
* every input's evidence checks out, and no input appears twice;
* no input is already spent by another operation (double spend);
* the same inputs were not already signed for a different output set (a retry with the same
  outputs is allowed: `k·B'` is deterministic, so it returns the same signatures);
* outputs ≤ inputs − input fees.

**Melt** (operation id: the melt quote)
* the proof check records the inputs as spent by this melt, so they can't be swapped
  afterwards. They are recorded as *unverified* until evidence arrives, so they block reuse but
  don't count as redeemed yet;
* signing change: the input checks above, and change ≤ inputs − fees − the amount paid out; for
  a bolt11 request the amount paid out must cover the invoice.

**Mint quote**
* issuance ≤ what the quotes were paid, minus what this guardian already helped issue against
  them (its own count, not the host's);
* a bolt11 payment hash backs one quote only, and a quote can't claim more paid than its invoice;
* the hourly cap applies here, so it now limits *new* money rather than all signing.

**No context**: refused, unless the guardian runs with `--allow-contextless` (v1 behaviour, for
a stock cdk-mintd).

**Every guardian learns every spend.** After a signature, the coordinator announces the
finished signatures *and* the operation, with its input evidence, to all guardians, signers or
not. The same happens after a melt's proof check. Each guardian checks the evidence and records
the spends. A guardian that learns of a spend conflicting with its own records logs
`DOUBLE SPEND`.

## What this buys

Swaps and melts can no longer create ecash, whoever runs the mint host or the coordinator.
New ecash can only come from a mint quote, and every guardian independently caps it, limits it
to once per quote and counts it. `outstanding = issued − redeemed` in each guardian's ledger
is the ecash in circulation, to compare with the mint's reserves.

`examples/evil_mintd.rs` acts as a compromised mint host against running guardians, and
`scripts/m4.sh` runs it. Its attempts to sign without context, over-issue, unbalance a swap,
swap a forged input, double-spend, or swap melted proofs are all refused.

## What it does not buy (yet)

* **Mint quotes are believed, within limits.** A guardian can't see a Lightning payment, and
  the mint created the invoice, so a claimed payment can't be proven. A dishonest host can
  still issue up to the cap against quotes that were never paid; the ledgers record it. Fixing
  this needs guardians with their own view of the payment (for example reserves on chain at an
  address the guardians control).
* **Double-spend protection relies on seeing the group's messages.** Guardians now learn of
  spends from each other's signed replies, not only from the coordinator, and replay what they
  missed before signing again (`docs/catch-up-and-ledger.md`). What remains is a relay that
  withholds messages, in collusion with t − 1 guardians.
* **Spending conditions** (P2PK, HTLC) are still checked by the mint only. A dishonest host can
  ignore a lock and let the wrong person spend a token. That moves existing ecash between
  users; it does not create any.
* **Failed melts.** Proofs from a melt that fails can afterwards only be retried for the same
  quote, because guardians have no signed notice that the melt failed.
* **Custody of reserves**, as before. (The trusted dealer is gone: see `docs/dkg.md`.)
