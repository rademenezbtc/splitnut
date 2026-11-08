//! On-disk formats written by the dealer: one public keyset file for the coordinator and one
//! share file per guardian. Points are 33-byte compressed hex, scalars 32-byte hex.

use std::collections::BTreeMap;
use std::path::Path;

use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};

use crate::{conv, Error, Idx};

pub const FORMAT_VERSION: u32 = 1;

/// Everything public about the dealt keyset: what the coordinator serves to cdk-mintd and
/// needs to check guardian shares. Contains no secrets.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKeyset {
    pub format: u32,
    pub t: u16,
    pub n: u16,
    pub unit: String,
    pub input_fee_ppk: u64,
    /// NUT-02 keyset id (hex), computed by the `cashu` crate from `keys`.
    pub keyset_id: String,
    /// Stable signer identity, reported to cdk-mintd as `SignatoryKeysets.pubkey`
    /// (it becomes the mint's NUT-06 pubkey; mintd refuses to start if it changes).
    pub identity_pubkey: String,
    /// Mint public key per amount, `K_a = k_a·G`.
    pub keys: BTreeMap<u64, String>,
    /// Each guardian's public share per amount, `K_{a,i} = k_{a,i}·G`.
    pub public_shares: BTreeMap<Idx, BTreeMap<u64, String>>,
}

/// One guardian's secret shares, plus the public keyset for self-checks.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardianShareFile {
    pub format: u32,
    pub index: Idx,
    /// Secret share per amount, `k_{a,i}`.
    pub shares: BTreeMap<u64, String>,
    pub keyset: PublicKeyset,
}

impl PublicKeyset {
    pub fn mint_key(&self, amount: u64) -> Result<ProjectivePoint, Error> {
        let hex = self.keys.get(&amount).ok_or(Error::InvalidPoint)?;
        point_hex(hex)
    }

    /// `{guardian index → K_{a,i}}` for one amount.
    pub fn public_shares_for(&self, amount: u64) -> Result<BTreeMap<Idx, ProjectivePoint>, Error> {
        self.public_shares
            .iter()
            .map(|(i, m)| {
                let hex = m.get(&amount).ok_or(Error::UnknownGuardian(*i))?;
                Ok((*i, point_hex(hex)?))
            })
            .collect()
    }

    pub fn amounts(&self) -> Vec<u64> {
        self.keys.keys().copied().collect()
    }
}

impl GuardianShareFile {
    /// Parse all shares and check each against the guardian's public share in the keyset.
    pub fn parse_shares(&self) -> Result<BTreeMap<u64, Scalar>, Error> {
        let pubs = self.keyset.public_shares.get(&self.index).ok_or(Error::UnknownGuardian(self.index))?;
        self.shares
            .iter()
            .map(|(amount, hex)| {
                let k_i = scalar_hex(hex)?;
                let expected = point_hex(pubs.get(amount).ok_or(Error::BadShare(self.index))?)?;
                if ProjectivePoint::GENERATOR * k_i != expected {
                    return Err(Error::BadShare(self.index));
                }
                Ok((*amount, k_i))
            })
            .collect()
    }
}

pub fn point_hex(s: &str) -> Result<ProjectivePoint, Error> {
    conv::point_from_bytes(&hex::decode(s).map_err(|_| Error::InvalidPoint)?)
}

pub fn scalar_hex(s: &str) -> Result<Scalar, Error> {
    conv::scalar_from_bytes(&hex::decode(s).map_err(|_| Error::InvalidScalar)?)
}

pub fn to_hex_point(p: &ProjectivePoint) -> Result<String, Error> {
    Ok(hex::encode(conv::point_to_bytes(p)?))
}

pub fn to_hex_scalar(s: &Scalar) -> String {
    hex::encode(conv::scalar_to_bytes(s))
}

/// Read a JSON file.
pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> std::io::Result<T> {
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(std::io::Error::other)
}

/// Deal a fresh keyset: one random key per amount `2^0..2^(max_order-1)`, each split t-of-n.
/// Returns the public keyset and one share file per guardian (index order). The keyset id is
/// the V2 id CDK computes for these keys, unit and fee (no final expiry).
pub fn deal(
    t: u16,
    n: u16,
    unit: &cashu::nuts::nut00::CurrencyUnit,
    input_fee_ppk: u64,
    max_order: u32,
    rng: &mut impl rand_core::CryptoRngCore,
) -> Result<(PublicKeyset, Vec<GuardianShareFile>), Error> {
    use k256::elliptic_curve::Field;
    if !(1..=64).contains(&max_order) {
        return Err(Error::InvalidThreshold { t, n });
    }
    let mut keys = BTreeMap::new();
    let mut cashu_keys = BTreeMap::new();
    let mut public_shares: BTreeMap<Idx, BTreeMap<u64, String>> = BTreeMap::new();
    let mut secret_shares: BTreeMap<Idx, BTreeMap<u64, String>> = BTreeMap::new();

    for amount in (0..max_order).map(|i| 1u64 << i) {
        let k = Scalar::random(&mut *rng);
        let k_pub = ProjectivePoint::GENERATOR * k;
        let shares = crate::shamir::split(&k, t, n, rng)?;
        // Self-check: the first t shares reconstruct K in the exponent.
        let first: Vec<_> = shares[..t as usize].iter().map(|(i, s)| (*i, ProjectivePoint::GENERATOR * s)).collect();
        if crate::shamir::combine_points(&first)? != k_pub {
            return Err(Error::CombinedInvalid);
        }
        keys.insert(amount, to_hex_point(&k_pub)?);
        cashu_keys.insert(cashu::Amount::from(amount), conv::public_key(&k_pub)?);
        for (i, s) in &shares {
            public_shares.entry(*i).or_default().insert(amount, to_hex_point(&(ProjectivePoint::GENERATOR * s))?);
            secret_shares.entry(*i).or_default().insert(amount, to_hex_scalar(s));
        }
    }

    let keyset_id = cashu::nuts::nut02::Id::v2_from_data(&cashu::nuts::nut01::Keys::new(cashu_keys), unit, input_fee_ppk, None);
    // Signer identity: a fresh key whose secret is discarded; mintd only checks it stays the same.
    let identity = ProjectivePoint::GENERATOR * Scalar::random(&mut *rng);

    let keyset = PublicKeyset {
        format: FORMAT_VERSION,
        t,
        n,
        unit: unit.to_string(),
        input_fee_ppk,
        keyset_id: keyset_id.to_string(),
        identity_pubkey: to_hex_point(&identity)?,
        keys,
        public_shares,
    };
    let files = secret_shares
        .into_iter()
        .map(|(index, shares)| GuardianShareFile { format: FORMAT_VERSION, index, shares, keyset: keyset.clone() })
        .collect::<Vec<_>>();
    for f in &files {
        f.parse_shares()?;
    }
    Ok((keyset, files))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn deal_roundtrip() {
        let unit = cashu::nuts::nut00::CurrencyUnit::Sat;
        let (ks, files) = deal(2, 3, &unit, 0, 32, &mut OsRng).unwrap();
        assert_eq!(ks.keys.len(), 32);
        assert!(ks.keyset_id.starts_with("01"), "V2 keyset id");
        assert_eq!(files.len(), 3);
        let json = serde_json::to_string(&files[0]).unwrap();
        let back: GuardianShareFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.parse_shares().unwrap().len(), 32);
        // a tampered share is caught on load
        let mut bad = files[1].clone();
        let first = *bad.shares.keys().next().unwrap();
        bad.shares.insert(first, to_hex_scalar(&Scalar::ONE));
        assert_eq!(bad.parse_shares(), Err(Error::BadShare(2)));
    }
}
