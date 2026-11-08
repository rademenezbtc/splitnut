# Spike findings (8 Nov 2026)

Read from source at **CDK v0.18.3** (tagged 28 Oct 2026), **mdk-core 0.8.0** (crates.io) and
**cashu-ts** master, then confirmed end to end with `scripts/spike.sh`.

## Result

cdk-mintd with no seed, signing through CDK's reference remote signatory over mTLS gRPC:
cdk-cli mints 1000 sat, sends 400 to a second wallet, which receives it; a double spend is
rejected; the second wallet melts 300. **Milestone 1's done-condition is met.**

With the signer stopped, a mint request fails in about 1 s with a clear "service unavailable"
error, with no hang. The paid quote stays claimable, so the wallet can claim it once signing is back.

## Answers to the open questions

| # | Question | Answer |
|---|----------|--------|
| 1 | Remote signer usable? Reference server? | Yes. `cdk_signatory::start_grpc_server<S: Signatory>` is **generic over the trait**, so the coordinator implements `Signatory` and reuses CDK's server, TLS and schema-version interceptor. No proto code of our own. Reference binary: `signatory`. |
| 2 | MDK networking? | `mdk-core 0.8.0` is MLS only: synchronous API, Nostr events in and out (`create_message`, `process_message`, welcomes, key packages). Relay I/O goes through `nostr-sdk 0.44` (same `nostr` 0.44 as mdk-core). MDK master has since become a large app runtime (White Noise, `publish = false`), so we pin the crates.io 0.8.0 line. |
| 3 | Amount and keyset in requests? | Yes. `BlindedMessage {amount, keyset_id, blinded_secret}`, `Proof {amount, keyset_id, secret, c}`. |
| 4 | Wallets reject missing DLEQ? | No. cdk wallet (`construct_proofs`) and cashu-ts (`OutputData`) treat DLEQ as optional but **reject an invalid one**. Single-round signing without DLEQ is fine for milestone 2; a wrong combined DLEQ fails loudly. Phone wallet still to be checked by hand. |
| 5 | Keys per keyset? | cdk-mintd default unit config: **32 amounts, 2^0 to 2^31**, fee 0. Keyset id is **V2** (`01…`, 33 bytes) by default. |
| 6 | Rotation with remote signing? | At startup `MintBuilder::build_with_signatory` calls `rotate_keyset` if there is no active keyset for a configured unit, or its fee or amounts differ. The dealer must therefore write exactly that keyset (sat, fee 0, 32 amounts, V2 id), and the coordinator refuses rotation. mintd also pins the signer's `SignatoryKeysets.pubkey` (it becomes the NUT-06 mint pubkey) and refuses to start if it changes, so the dealer writes a stable identity key. |
| 7 | Marmot round-trip latency | To measure in milestone 3. |
| 8 | Value4Value | Ask the organisers on Nostr. |

## Gotchas hit

* **v0.18 config lives in the database.** `--config` is gone: run
  `cdk-mintd --work-dir D config init --new-mint --file mintd.toml` once, then `cdk-mintd --work-dir D`.
  The legacy `[ln]` table is now `[payment_backend]` plus `[onchain]`.
* **CDK's `generate_certs.sh` issues an X.509 v1 client cert**, which rustls rejects. cdk-mintd
  then fails with only "transport error". Our `scripts/gen-certs.sh` issues v3 certs. Worth a
  one-line upstream PR to CDK, which also counts as "improving Cashu".
* Building CDK needs `protoc`. CDK's `rust-toolchain.toml` pins 1.97.1; stable 1.97.0 builds it fine.
* cdk-cli needs `--allow-untrusted` to receive tokens from a mint it hasn't added.

## Pinned versions

`cashu`, `cdk-common`, `cdk-signatory` `=0.18.3`; `mdk-core`, `mdk-memory-storage` `=0.8.0`;
`nostr-sdk 0.44`. The whole workspace resolves and compiles together.

## Design consequences

* `splitnut-coord` = `impl Signatory` plus a call to `start_grpc_server`.
* `keysets()` / `subscribe_keysets()` return the dealer's public keyset; `rotate_keyset()` returns
  `ERROR_CODE_COULD_NOT_ROTATE_KEYSET`.
* With fewer than t guardians answering, return a signer error quickly (for example
  `MINTING_DISABLED` with "quorum unavailable"); mintd surfaces it cleanly to the wallet.
* mdk-core is synchronous: wrap each MDK instance in one mutex and drive it from a single task
  that also owns the relay subscription. This is the BlackIce "serialise all MLS operations" lesson.
