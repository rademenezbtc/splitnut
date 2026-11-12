//! The coordinator's part of distributed key generation: a relay and a referee, never a
//! party to the key.
//!
//! 1. Ask every guardian to deal (`DkgStart`); collect each one's commitments and its shares
//!    for the others, which are NIP-44-encrypted to their recipients and unreadable here.
//! 2. Send each guardian every dealer's commitments plus the shares dealt to it (`DkgDeals`).
//! 3. Each guardian checks its shares, builds its share file and reports the keyset it got.
//!    The coordinator computes the public keyset from the commitments itself and writes it
//!    only if every guardian reported exactly that keyset.
//!
//! All n guardians must take part; any refusal aborts the ceremony with the reason.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use cdk_common::CurrencyUnit;
use futures::future::join_all;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use splitnut_core::guardian::RequestId;
use splitnut_core::keyfile::{assemble, PublicKeyset};
use splitnut_core::{dkg, Idx};
use splitnut_proto::{commitments_from_wire, RequestBody, ResponseBody};
use tracing::info;

use crate::marmot_link::Hub;

pub struct Params {
    pub t: u16,
    pub n: u16,
    pub unit: CurrencyUnit,
    pub input_fee_ppk: u64,
    pub amounts: Vec<u64>,
}

fn keyset_hash(k: &PublicKeyset) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(k).expect("keyset serialises")))
}

pub async fn run(hub: Arc<Hub>, indices: &[Idx], p: &Params, mut req: RequestId, timeout: Duration) -> Result<PublicKeyset> {
    let mut sid = [0u8; 8];
    OsRng.fill_bytes(&mut sid);
    let session = hex::encode(sid);
    info!(session, t = p.t, n = p.n, keys = p.amounts.len(), "key generation: asking every guardian to deal");

    // Step 1: deals.
    req += 1;
    let start = RequestBody::DkgStart {
        session: session.clone(),
        t: p.t,
        n: p.n,
        unit: p.unit.to_string(),
        input_fee_ppk: p.input_fee_ppk,
        amounts: p.amounts.clone(),
    };
    let replies = join_all(indices.iter().map(|i| {
        let hub = hub.clone();
        let body = start.clone();
        async move { (*i, tokio::time::timeout(timeout, hub.call(*i, req, body)).await) }
    }))
    .await;
    let mut commitments: BTreeMap<Idx, Vec<Vec<String>>> = BTreeMap::new();
    let mut shares: BTreeMap<Idx, BTreeMap<Idx, String>> = BTreeMap::new(); // dealer -> recipient -> ciphertext
    for (i, r) in replies {
        match r {
            Ok(Ok(ResponseBody::DkgDeal { session: s, commitments: c, shares: sh })) if s == session => {
                let parsed = commitments_from_wire(&c).with_context(|| format!("guardian {i}'s commitments"))?;
                if !dkg::check_commitments(&parsed, p.t, p.amounts.len()) {
                    bail!("guardian {i} sent malformed commitments");
                }
                commitments.insert(i, c);
                shares.insert(i, sh.into_iter().collect());
            }
            Ok(Ok(other)) => bail!("guardian {i} answered {} instead of a deal", other.kind()),
            Ok(Err(e)) => bail!("guardian {i}: {e}"),
            Err(_) => bail!("guardian {i} did not deal within {} s", timeout.as_secs()),
        }
    }
    info!("all {} guardians dealt; passing each its shares", indices.len());

    // Step 2: each guardian gets all commitments and the shares dealt to it.
    req += 1;
    let replies = join_all(indices.iter().map(|j| {
        let hub = hub.clone();
        let body = RequestBody::DkgDeals {
            session: session.clone(),
            commitments: commitments.iter().map(|(d, c)| (*d, c.clone())).collect(),
            shares: shares.iter().filter_map(|(d, m)| m.get(j).map(|s| (*d, s.clone()))).collect(),
        };
        async move { (*j, tokio::time::timeout(timeout, hub.call(*j, req, body)).await) }
    }))
    .await;

    // The public keyset, from the commitments alone.
    let parsed: BTreeMap<Idx, _> =
        commitments.iter().map(|(d, c)| Ok((*d, commitments_from_wire(c)?))).collect::<Result<_, splitnut_core::Error>>()?;
    let (keys, public_shares) = dkg::public_outcome(&parsed, p.n);
    let keyset = assemble(p.t, p.n, &p.unit, p.input_fee_ppk, &p.amounts, &keys, &public_shares)?;
    let want = keyset_hash(&keyset);
    for (j, r) in replies {
        match r {
            Ok(Ok(ResponseBody::DkgDone { session: s, keyset_id, keyset_hash })) if s == session => {
                if keyset_id != keyset.keyset_id || keyset_hash != want {
                    bail!("guardian {j} computed a different keyset ({keyset_id}); ceremony aborted");
                }
                info!(guardian = j, keyset = %keyset_id, "guardian confirmed the keyset");
            }
            Ok(Ok(other)) => bail!("guardian {j} answered {} instead of confirming", other.kind()),
            Ok(Err(e)) => bail!("guardian {j}: {e}"),
            Err(_) => bail!("guardian {j} did not confirm within {} s", timeout.as_secs()),
        }
    }
    Ok(keyset)
}
