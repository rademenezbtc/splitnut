//! The guardian's part of distributed key generation (see `splitnut_core::dkg`).
//!
//! Step 1 (`DkgStart`): deal a random polynomial per mint key. Commitments go to everyone,
//! and each other guardian's shares are NIP-44-encrypted from this guardian's Nostr key to
//! theirs, so the coordinator relaying them cannot read them.
//!
//! Step 2 (`DkgDeals`): decrypt the shares dealt to this guardian, check each against its
//! dealer's commitments, check the coordinator relayed this guardian's own commitments
//! unchanged, and sum. The result is a normal share file. The public keyset is computed from
//! the commitments, and its hash is reported so the coordinator can confirm everyone agrees.
//!
//! Guardians' Nostr keys come from the local roster file, never from the coordinator, so a
//! coordinator cannot slip in its own key and receive a guardian's shares.

use std::collections::BTreeMap;
use std::str::FromStr;

use cashu::nuts::nut00::CurrencyUnit;
use nostr_sdk::nips::nip44;
use nostr_sdk::prelude::{Keys, PublicKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use splitnut_core::dkg;
use splitnut_core::keyfile::{scalar_hex, share_file_from_dkg, to_hex_scalar, GuardianShareFile, PublicKeyset};
use splitnut_core::{Idx, Scalar};
use splitnut_proto::{commitments_from_wire, commitments_to_wire, ResponseBody};

/// A ceremony in progress: what this guardian dealt.
pub struct Ceremony {
    pub session: String,
    index: Idx,
    t: u16,
    n: u16,
    unit: CurrencyUnit,
    input_fee_ppk: u64,
    amounts: Vec<u64>,
    deal: dkg::Deal,
}

/// Hash of a public keyset's canonical JSON (struct field order, sorted maps).
pub fn keyset_hash(k: &PublicKeyset) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(k).expect("keyset serialises")))
}

fn encrypt_shares(keys: &Keys, to: &PublicKey, shares: &[Scalar]) -> Result<String, String> {
    let plain = serde_json::to_string(&shares.iter().map(to_hex_scalar).collect::<Vec<_>>()).map_err(|e| e.to_string())?;
    nip44::encrypt(keys.secret_key(), to, plain, nip44::Version::V2).map_err(|e| format!("nip44: {e}"))
}

fn decrypt_shares(keys: &Keys, from: &PublicKey, payload: &str) -> Result<Vec<Scalar>, String> {
    let plain = nip44::decrypt(keys.secret_key(), from, payload).map_err(|e| format!("nip44: {e}"))?;
    let hexes: Vec<String> = serde_json::from_str(&plain).map_err(|e| e.to_string())?;
    hexes.iter().map(|h| scalar_hex(h).map_err(|e| e.to_string())).collect()
}

/// Step 1: deal. Returns the ceremony state and the `DkgDeal` answer.
#[allow(clippy::too_many_arguments)]
pub fn start(
    keys: &Keys,
    roster: &BTreeMap<Idx, PublicKey>,
    session: &str,
    t: u16,
    n: u16,
    unit: &str,
    input_fee_ppk: u64,
    amounts: &[u64],
) -> Result<(Ceremony, ResponseBody), String> {
    let index = *roster
        .iter()
        .find(|(_, pk)| **pk == keys.public_key())
        .ok_or("this guardian's key is not in the roster")?
        .0;
    if roster.len() != n as usize || roster.keys().copied().ne(1..=n) {
        return Err(format!("roster has guardians {:?}, the ceremony is for 1..={n}", roster.keys().collect::<Vec<_>>()));
    }
    if amounts.is_empty() || amounts.len() > 64 {
        return Err("bad amounts".into());
    }
    let unit = CurrencyUnit::from_str(unit).map_err(|_| format!("unknown unit {unit}"))?;
    let deal = dkg::deal(t, n, amounts.len(), &mut OsRng).map_err(|e| e.to_string())?;
    let mut shares = vec![];
    for (j, pk) in roster {
        if *j != index {
            shares.push((*j, encrypt_shares(keys, pk, &deal.shares[j])?));
        }
    }
    let body = ResponseBody::DkgDeal {
        session: session.to_string(),
        commitments: commitments_to_wire(&deal.commitments).map_err(|e| e.to_string())?,
        shares,
    };
    let c = Ceremony { session: session.to_string(), index, t, n, unit, input_fee_ppk, amounts: amounts.to_vec(), deal };
    Ok((c, body))
}

/// Step 2: check and combine. Returns this guardian's share file and the `DkgDone` answer.
pub fn finish(
    c: &Ceremony,
    keys: &Keys,
    roster: &BTreeMap<Idx, PublicKey>,
    commitments: &[(Idx, Vec<Vec<String>>)],
    shares: &[(Idx, String)],
) -> Result<(GuardianShareFile, ResponseBody), String> {
    let commitments: BTreeMap<Idx, Vec<Vec<String>>> = commitments.iter().cloned().collect();
    let mine = commitments_to_wire(&c.deal.commitments).map_err(|e| e.to_string())?;
    if commitments.get(&c.index) != Some(&mine) {
        return Err(format!("refused: the coordinator altered guardian {}'s own commitments", c.index));
    }
    let mut parsed = BTreeMap::new();
    for (d, w) in &commitments {
        parsed.insert(*d, commitments_from_wire(w).map_err(|e| format!("refused: guardian {d}'s commitments: {e}"))?);
    }
    let mut received = BTreeMap::new();
    received.insert(c.index, c.deal.shares[&c.index].clone());
    for (d, payload) in shares {
        if *d == c.index {
            continue;
        }
        let from = roster.get(d).ok_or(format!("refused: shares from unknown guardian {d}"))?;
        let s = decrypt_shares(keys, from, payload)
            .map_err(|e| format!("refused: shares from guardian {d} do not decrypt with its key ({e})"))?;
        received.insert(*d, s);
    }
    let out = dkg::finish(c.index, c.t, c.n, c.amounts.len(), &parsed, &received).map_err(|e| match e {
        splitnut_core::Error::BadShare(d) => format!("refused: guardian {d} dealt an invalid share"),
        splitnut_core::Error::MissingShare(d) => format!("refused: nothing from guardian {d}"),
        e => format!("refused: {e}"),
    })?;
    let file = share_file_from_dkg(c.index, c.t, c.n, &c.unit, c.input_fee_ppk, &c.amounts, &out).map_err(|e| e.to_string())?;
    let body = ResponseBody::DkgDone {
        session: c.session.clone(),
        keyset_id: file.keyset.keyset_id.clone(),
        keyset_hash: keyset_hash(&file.keyset),
    };
    Ok((file, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use splitnut_core::guardian::{Guardian, SignItem};
    use splitnut_core::{conv, sign, ProjectivePoint};

    fn amounts() -> Vec<u64> {
        vec![1, 2, 4, 8]
    }

    /// Run a ceremony with the coordinator's relaying done inline; `tamper` may change the
    /// deals before they are passed on.
    fn ceremony(tamper: impl Fn(&mut BTreeMap<Idx, ResponseBody>)) -> Vec<Result<(GuardianShareFile, ResponseBody), String>> {
        let keys: Vec<Keys> = (0..3).map(|_| Keys::generate()).collect();
        let roster: BTreeMap<Idx, PublicKey> = keys.iter().enumerate().map(|(i, k)| (i as Idx + 1, k.public_key())).collect();
        let mut states = vec![];
        let mut deals = BTreeMap::new();
        for (i, k) in keys.iter().enumerate() {
            let (c, deal) = start(k, &roster, "s1", 2, 3, "sat", 0, &amounts()).unwrap();
            states.push(c);
            deals.insert(i as Idx + 1, deal);
        }
        tamper(&mut deals);
        let commitments: Vec<(Idx, Vec<Vec<String>>)> = deals
            .iter()
            .map(|(d, b)| match b {
                ResponseBody::DkgDeal { commitments, .. } => (*d, commitments.clone()),
                _ => unreachable!(),
            })
            .collect();
        (1..=3u16)
            .map(|j| {
                let shares: Vec<(Idx, String)> = deals
                    .iter()
                    .filter_map(|(d, b)| match b {
                        ResponseBody::DkgDeal { shares, .. } => shares.iter().find(|(r, _)| *r == j).map(|(_, s)| (*d, s.clone())),
                        _ => None,
                    })
                    .collect();
                finish(&states[j as usize - 1], &keys[j as usize - 1], &roster, &commitments, &shares)
            })
            .collect()
    }

    #[test]
    fn guardians_agree_and_can_sign() {
        let results = ceremony(|_| {});
        let files: Vec<GuardianShareFile> = results.into_iter().map(|r| r.unwrap().0).collect();
        assert!(files.iter().all(|f| f.keyset == files[0].keyset), "same public keyset everywhere");
        // Guardians 1 and 3 produce a valid threshold signature under the DKG key.
        let mut g1 = Guardian::from_file(&files[0]).unwrap();
        let mut g3 = Guardian::from_file(&files[2]).unwrap();
        let b = conv::hash_to_curve(b"blinded").unwrap();
        let item = [SignItem { amount: 8, b }];
        let r1 = g1.round1(1, &item, &mut OsRng).unwrap()[0];
        let r3 = g3.round1(1, &item, &mut OsRng).unwrap()[0];
        let k = files[0].keyset.mint_key(8).unwrap();
        let session = sign::Session::new(k, b, vec![(1, r1), (3, r3)]).unwrap();
        let e = session.challenge();
        let s1 = g1.round2(1, &item, &[e]).unwrap()[0];
        let s3 = g3.round2(1, &item, &[e]).unwrap()[0];
        let shares = files[0].keyset.public_shares_for(8).unwrap();
        let (c, _, _) = session.finish(&shares, &[(1, s1), (3, s3)]).unwrap();
        assert_ne!(c, ProjectivePoint::IDENTITY);
    }

    #[test]
    fn a_tampered_share_is_caught_and_its_dealer_named() {
        // Guardian 2 re-encrypts garbage to guardian 1 (the coordinator cannot do this: it
        // would not decrypt under guardian 2's key).
        let results = ceremony(|deals| {
            if let Some(ResponseBody::DkgDeal { commitments, .. }) = deals.get_mut(&2) {
                commitments[0][0] = commitments[1][0].clone();
            }
        });
        let err = results[0].as_ref().err().map(String::as_str).unwrap_or("");
        assert!(err.contains("guardian 2 dealt an invalid share"), "{err}");
        // guardian 2 notices its own commitments were changed in transit
        let err = results[1].as_ref().err().unwrap();
        assert!(err.contains("altered guardian 2's own commitments"), "{err}");
    }
}
