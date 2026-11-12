# Distributed key generation

The trusted dealer generated every mint key, split it, and handed out the shares, so whoever
ran it saw every key and, with a copy, could sign without any guardian. Now the guardians
generate the keys among themselves, and no one ever sees a whole key.

## The scheme (joint Feldman VSS)

For each of the 32 mint keys, every guardian `d`:

1. picks a random polynomial `f_d` of degree t−1;
2. publishes Feldman commitments `C_{d,k} = a_{d,k}·G` to its coefficients;
3. gives every other guardian `j` the share `f_d(j)`, encrypted to `j`.

Guardian `j` checks each share against its dealer's commitments, `f_d(j)·G = Σ_k j^k·C_{d,k}`,
then:

* its share of the key is `k_j = Σ_d f_d(j)`;
* the mint public key is `K = Σ_d C_{d,0}`;
* every guardian's public share is `K_i = Σ_d Σ_k i^k·C_{d,k}`, which anyone can compute.

The key itself, `Σ_d f_d(0)`, is never computed. The result has the same form as a dealer's
Shamir sharing, so signing, proof checks and the guardian rules are unchanged. The signer
identity that cdk-mintd pins (its NUT-06 pubkey) is derived from the keyset id by hash to
curve, so it is the same everywhere and nobody knows its discrete log.

## The ceremony over Marmot

The coordinator relays and referees. It never receives anything that would let it compute a
share.

| Step | From → to | Content |
|------|-----------|---------|
| `DkgStart` | coordinator → each guardian | session, t, n, unit, fee, amounts |
| `DkgDeal` | guardian → coordinator | commitments; for each other guardian, its shares NIP-44-encrypted from this guardian's Nostr key to theirs |
| `DkgDeals` | coordinator → each guardian | every dealer's commitments, and the ciphertexts addressed to that guardian |
| `DkgDone` | guardian → coordinator | the keyset id and a hash of the whole public keyset |

All of it travels inside the MLS group, so relays see only ciphertext. Each guardian also
checks that:

* every share decrypts under its dealer's roster key. NIP-44's key is the ECDH of sender and
  recipient, so the coordinator cannot forge a share "from" a guardian;
* every share matches its dealer's commitments; otherwise it refuses and names the dealer;
* its own commitments came back unchanged.

The coordinator computes the public keyset from the commitments itself and writes
`public.json` only if all n guardians reported exactly that keyset. Each guardian writes its
own share file (mode 0600) and exits; `run` then resumes the same group.

Guardians take each other's Nostr keys from their own copy of the roster, never from the
coordinator. A coordinator that could choose the roster could put its own key in a guardian's
place and receive that guardian's shares.

## Limits

* **All n guardians must take part.** The ceremony needs everyone online at once, and any
  invalid share aborts it, naming the dealer, rather than excluding that dealer and carrying on.
* **Key bias.** In joint Feldman a dealer that sees the others' commitments before publishing
  its own can bias the public key's distribution (Gennaro, Jarecki, Krawczyk and Rabin, 1999).
  It cannot learn the key. Here all dealers commit in the same round through the coordinator,
  so this needs the coordinator to collude with a guardian. Pedersen-based DKG (GJKR) would
  remove the bias, at the cost of an extra round.
* **No resharing.** Changing the guardian set, or replacing one, means a new keyset (a new
  ceremony) and a CDK keyset rotation, which SplitNut does not do yet.

## Tests

* `splitnut-core`: any t of the generated shares reconstruct each public key; a bad share names
  its dealer; DKG share files have the same form as dealt ones.
* `splitnut-guardian`: a three-guardian ceremony with real NIP-44 encryption ends with the same
  keyset everywhere and a working threshold signature. Tampered commitments are caught by the
  receiving guardians (the dealer is named) and by the dealer whose commitments were altered.
* `scripts/m4.sh` and `scripts/demo.sh` run the ceremony over Marmot, then the whole wallet flow
  and the attack run, on the generated keys.
