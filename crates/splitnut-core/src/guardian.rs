//! Guardian state machine: holds one share of every mint key and answers signing and
//! verification requests. Transport-free; the in-memory guardians (milestone 2) and the
//! Marmot guardian daemon (milestone 3) both wrap this.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use k256::{ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;

use crate::keyfile::GuardianShareFile;
use crate::sign::{self, Nonce, Round1};
use crate::verify::{self, Partial};
use crate::{Error, Idx};

/// Request id chosen by the coordinator; ties round 2 to the nonces of round 1.
pub type RequestId = u64;

/// One item to sign: the amount picks the share, `b` is the blinded message `B'`.
#[derive(Clone, Copy, Debug)]
pub struct SignItem {
    pub amount: u64,
    pub b: ProjectivePoint,
}

/// One proof to check: the amount picks the share, `y = hash_to_curve(secret)`.
#[derive(Clone, Copy, Debug)]
pub struct VerifyItem {
    pub amount: u64,
    pub y: ProjectivePoint,
}

pub struct Guardian {
    index: Idx,
    keyset_id: String,
    shares: BTreeMap<u64, Scalar>,
    /// Round-1 nonces waiting for round 2, per request, with when they were made.
    pending: HashMap<RequestId, (Instant, Vec<Nonce>)>,
}

/// Unused round-1 nonces are dropped after this long (an abort may have overtaken its
/// request on the relay, or the coordinator may have gone away).
pub const NONCE_TTL: Duration = Duration::from_secs(120);

impl Guardian {
    pub fn new(index: Idx, keyset_id: String, shares: BTreeMap<u64, Scalar>) -> Self {
        Self { index, keyset_id, shares, pending: HashMap::new() }
    }

    /// Load from a dealer share file, checking every share against its public share.
    pub fn from_file(file: &GuardianShareFile) -> Result<Self, Error> {
        Ok(Self::new(file.index, file.keyset.keyset_id.clone(), file.parse_shares()?))
    }

    pub fn index(&self) -> Idx {
        self.index
    }

    pub fn keyset_id(&self) -> &str {
        &self.keyset_id
    }

    fn share(&self, amount: u64) -> Result<&Scalar, Error> {
        self.shares.get(&amount).ok_or(Error::InvalidScalar)
    }

    /// Round 1 for a batch. Fresh nonces are stored until [`Self::round2`] or [`Self::abort`].
    /// A repeated request id is refused, so a nonce can never be used twice.
    pub fn round1(
        &mut self,
        req: RequestId,
        items: &[SignItem],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<Round1>, Error> {
        self.pending.retain(|_, (made, _)| made.elapsed() < NONCE_TTL);
        if self.pending.contains_key(&req) {
            return Err(Error::InvalidSignerSet);
        }
        let mut nonces = Vec::with_capacity(items.len());
        let mut out = Vec::with_capacity(items.len());
        for it in items {
            let (nonce, r1) = sign::round1(self.share(it.amount)?, &it.b, rng);
            nonces.push(nonce);
            out.push(r1);
        }
        self.pending.insert(req, (Instant::now(), nonces));
        Ok(out)
    }

    /// Round 2 for a batch: one challenge per item, in round-1 order. Consumes the nonces.
    pub fn round2(&mut self, req: RequestId, items: &[SignItem], es: &[Scalar]) -> Result<Vec<Scalar>, Error> {
        let (_, nonces) = self.pending.remove(&req).ok_or(Error::MissingShare(self.index))?;
        if nonces.len() != es.len() || items.len() != es.len() {
            return Err(Error::NotEnoughShares { need: nonces.len(), got: es.len() });
        }
        nonces
            .into_iter()
            .zip(items.iter().zip(es))
            .map(|(nonce, (it, e))| Ok(sign::round2(nonce, self.share(it.amount)?, e)))
            .collect()
    }

    /// Drop the nonces of a request that will not reach round 2.
    pub fn abort(&mut self, req: RequestId) {
        self.pending.remove(&req);
    }

    /// Partial evaluations with DLEQs for a batch of proofs.
    pub fn verify(&self, items: &[VerifyItem], rng: &mut impl CryptoRngCore) -> Result<Vec<Partial>, Error> {
        items
            .iter()
            .map(|it| verify::partial(self.share(it.amount)?, &it.y, rng))
            .collect()
    }

    /// Number of requests holding nonces (for tests and the dashboard).
    pub fn pending_requests(&self) -> usize {
        self.pending.len()
    }
}
