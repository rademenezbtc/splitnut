# Nut November submission kit

Everything to paste into the form at nutnovember.org/form, plus posts for Nostr and X.
Replace the bracketed placeholders before submitting.

## Name and one-liner

**SplitNut**: a Cashu mint whose signing key is split across guardians, so no single
operator can create ecash on their own.

## Links

* Repository: https://github.com/rademenezbtc/splitnut (MIT)
* Demo video (2:03): [video link]
* Slides: [deck link, shared from claude.ai, or the exported PDF]
* Run it yourself: `docs/RUNNING.md`, one command (`scripts/demo.sh`)

## Description (short)

Today a Cashu mint's keys sit with one operator, who can sign unbacked ecash that no wallet
can detect. SplitNut splits every mint key 2-of-3 across guardians who coordinate over Marmot
(MLS over Nostr). Stock cdk-mintd hands all signing to SplitNut as its remote signer and holds
no keys itself; the guardians produce threshold signatures with standard NUT-12 DLEQ proofs,
so any Cashu wallet works unchanged. Each guardian enforces an hourly cap and keeps its own
ledger of DLEQ-verified issuance, and a live dashboard shows every request, the guardians'
ledgers and what the relay saw (ciphertext only). Kill one guardian and the mint keeps
working; kill two and it refuses, so the operator alone cannot print money.

## Notes (existing work vs. November)

New repository, all work from November 2026 (first commit 8 Nov). Design ideas carried over
from BlackIce (bitcoin++ Seoul, distributed FROST silent payments over Marmot); no code
reused. Built in Rust on CDK v0.18.3 (cdk-signatory, cashu crate), mdk-core 0.8 and
nostr-sdk 0.44. AI coding tools were used throughout, as the rules encourage.

Built in November:
* threshold maths (Shamir shares, Lagrange combination, two-round threshold blind signature
  with a standard NUT-12 DLEQ, threshold proof checks), tested against the cashu crate's own
  verification;
* a dealer, a coordinator implementing CDK's Signatory trait, and guardian daemons over a
  Marmot group with encrypted MLS state;
* guardian rules (hourly cap, independent ledgers, pinned identities, explained refusals),
  heartbeats, request batching for relay rate limits;
* a live dashboard, a local relay with a wire tap, end-to-end scripts and a one-command demo.

## Talking points

* Wallets cannot tell: the combined signature equals the single-key one, and wallets verify
  its DLEQ against the published keys.
* No fork: cdk-mintd's remote-signer support does all the integration; SplitNut only
  implements CDK's Signatory trait.
* Honest limits: the signer API carries no operation context, so guardians cannot yet check
  that swaps balance or quotes were paid; the proposed fix is a small CDK change.
* [Check before using] A remote-signer NUT is being drafted (cashubtc/nuts#250, "Mint Remote
  signer standard" in the Cashu dev-call notes). SplitNut is a working threshold
  implementation of such a signer, which could inform that standard.

## Post for Nostr and X

> Built SplitNut for #NutNovember: a Cashu mint where no single operator can print ecash.
> Every mint key is split 2-of-3 across guardians talking over Marmot. Stock cdk-mintd, no
> keys on the server, and any Cashu wallet works unchanged. Kill one guardian: still works.
> Kill two: it refuses. [video link] https://github.com/rademenezbtc/splitnut

Shorter:

> A Cashu mint the operator can't print from: keys split 2-of-3 across guardians over Marmot,
> wallets unchanged. #NutNovember [video link]

## Checklist (from the brief)

* [x] Public GitHub repo, first commit dated in November
* [x] LICENSE (MIT)
* [x] README leads with problem, solution and demo; run steps and threat model follow
* [x] One command starts the relay, three guardians, the coordinator and cdk-mintd
* [x] End-to-end test: mint, swap, melt through 2-of-3, one guardian down, two down
* [x] Demo video, 2 to 3 minutes: first cut ready, [upload and link it from the README]
* [x] Short deck (problem, how it works, demo, limits, next)
* [ ] Run on public relays from a real machine
* [ ] Try a phone wallet against the mint
* [ ] Submit by 26 Nov (deadline 27 Nov 23:59 UTC); no commits after the deadline
* [ ] Optional: present at the 17 Nov show-and-tell; post on Nostr and X
