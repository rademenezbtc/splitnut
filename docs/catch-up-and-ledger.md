# Catch-up and public ledgers

## The gap

Operation context made every guardian refuse double spends, but only double spends it knew
about. A guardian learned of spends it did not sign itself from the coordinator's
announcements. So a guardian that was offline, or that the coordinator simply left out, could
miss a spend. With 2-of-3 and one colluding guardian, the coordinator could then route a second
spend of the same proofs to the colluder and that uninformed guardian, and get it signed. The
guardians' ledgers had the same weakness: a quiet coordinator could make issuance look smaller.

## Learning spends from each other

Every message in the Marmot group reaches every member, whoever it is addressed to. So each
guardian sees every signing request, and every other guardian's reply to it.

* When a guardian approves an operation, its reply carries `approved`: a digest of the request
  kind, its outputs and its operation context (`approval_digest`).
* Every guardian keeps the recent requests it has seen. When a peer's reply carries a digest
  that matches one of them, it applies that operation's spends and issuance. The inputs carry
  evidence of being genuine, so this needs no trust in the peer for validity, only for the fact
  that it approved.
* Replies are authenticated by MLS (MDK binds each message to its sender's credential) and come
  from the guardians themselves. The coordinator cannot suppress them.
* Issuance is counted when outputs are approved, by this guardian or a peer, rather than when
  the coordinator announces the finished signatures. The coordinator's announcements are still
  applied, now whatever their age. Everything is keyed by `B'` or `Y`, so each output and each
  spend counts once however many routes it arrives by.

## Catching up after being offline

A restarted guardian resumes its MLS group, then:

1. fetches the group's stored history from the relays and processes it **oldest first**. MLS
   tolerates only a few out-of-order messages per sender, and relays usually return newest
   first, so sorting matters. Messages it had already processed are rejected by MDK and skipped;
2. applies everything it missed: peers' approvals, announcements, melt spends;
3. only then reports itself *synced*. Until then it refuses to sign or check proofs ("catching
   up on group messages missed while offline"), and the coordinator counts it as unavailable.

Replayed messages are queued ahead of live ones, so any request it answers comes after
everything it missed.

In `scripts/m4.sh`, guardian 1 is killed partway through and misses a swap, two mints and the
whole attack run. On restart it replays about 110 messages, then reports exactly the same issued,
redeemed and outstanding totals as the other two, with an identical digest.

## Public ledgers

Every `--publish-secs` (default 30), each guardian publishes its ledger as an ordinary Nostr
event signed with its own key: kind 30078 (NIP-78 application data, replaceable), `d` tag
`splitnut-ledger/<keyset id>`. The content:

```json
{ "keyset": "01…", "guardian": 2, "unit": "sat",
  "issued": 1649, "redeemed": 849, "outstanding": 800,
  "issued_last_hour": 1164, "cap_per_hour": 5000, "double_spend_attempts": 1,
  "digest": "d844ef…" }
```

`digest` is a hash of exactly which outputs (`B'`) this guardian counts as issued and which
proofs (`Y`) as redeemed. Guardians that saw the same history publish the same digest, so
agreement on the totals can be told apart from agreement on the details.

Anyone with the roster (the guardians' npubs) can audit the mint without access to it or to
the group:

```sh
cargo run -p splitnut-coord --example audit -- --roster roster.json --relay wss://… \
    [--require-all] [--expect-outstanding 800]
```

The audit checks signatures and authors against the roster, then that the reporting guardians
agree. Outstanding ecash should never exceed the mint's reserves. Proving the reserves is the
operator's part: SplitNut proves the liabilities side.

The wire tap in `splitnut-relay` now scans only private kinds (group messages and welcomes);
the ledger events are public on purpose.

## Limits

* **Relays that withhold.** A relay operator colluding with t − 1 guardians could keep messages
  from the others. Use several relays, at least one not run by the mint operator.
* **Drops while online.** A message lost while a guardian is running (a broadcast-channel
  overflow, logged as a warning) is not recovered until the next restart.
* **Approved is not completed.** An operation one guardian approved but that never completed
  (its peers refused) still counts as issued. That overstates liabilities, which is the safe
  direction.
* **History retention.** Catch-up needs the relays to keep the group's history for as long as a
  guardian might be offline.
