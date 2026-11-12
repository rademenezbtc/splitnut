//! Distributed key generation (joint Feldman VSS), replacing the trusted dealer.
//!
//! For each mint key, every guardian `d` picks a random polynomial `f_d` of degree t−1,
//! publishes Feldman commitments `C_{d,k} = a_{d,k}·G` to its coefficients, and gives guardian
//! `j` the share `f_d(j)` privately. Guardian `j` checks each share against the dealer's
//! commitments, `f_d(j)·G = Σ_k j^k·C_{d,k}`. Then:
//!
//! * `j`'s share of the key is `k_j = Σ_d f_d(j)`;
//! * the mint public key is `K = Σ_d C_{d,0}` (the key itself, `Σ_d f_d(0)`, is never computed
//!   by anyone);
//! * every guardian's public share is `K_j = Σ_d Σ_k j^k·C_{d,k}`, computable by anyone.
//!
//! This is the same Shamir sharing the dealer produced, so signing is unchanged.
//!
//! Known limit of joint Feldman (Gennaro et al., 1999): a dealer that sees the others'
//! commitments before publishing its own can bias the public key's distribution. That does
//! not let it learn the key. Here every dealer commits in the same round, through the
//! coordinator, so this needs a coordinator colluding with a guardian. A ceremony with any
//! invalid share is aborted (and the cheater named), not repaired.

use std::collections::BTreeMap;

use k256::elliptic_curve::Field;
use k256::{ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;

use crate::{Error, Idx};

/// One dealer's contribution for `keys` mint keys.
#[derive(Clone, Debug)]
pub struct Deal {
    /// Per key: commitments to the t coefficients, constant term first.
    pub commitments: Vec<Vec<ProjectivePoint>>,
    /// Per recipient (1..=n): one share per key.
    pub shares: BTreeMap<Idx, Vec<Scalar>>,
}

fn eval_poly(coeffs: &[Scalar], x: Idx) -> Scalar {
    let x = Scalar::from(x as u64);
    coeffs.iter().rev().fold(Scalar::ZERO, |acc, c| acc * x + c)
}

/// `Σ_k x^k·C_k`: the public value of the committed polynomial at `x`.
pub fn eval_commitments(commitments: &[ProjectivePoint], x: Idx) -> ProjectivePoint {
    let x = Scalar::from(x as u64);
    commitments.iter().rev().fold(ProjectivePoint::IDENTITY, |acc, c| acc * x + c)
}

/// Deal fresh random polynomials for `keys` keys, t-of-n.
pub fn deal(t: u16, n: u16, keys: usize, rng: &mut impl CryptoRngCore) -> Result<Deal, Error> {
    if t == 0 || t > n {
        return Err(Error::InvalidThreshold { t, n });
    }
    let mut commitments = Vec::with_capacity(keys);
    let mut shares: BTreeMap<Idx, Vec<Scalar>> = (1..=n).map(|j| (j, Vec::with_capacity(keys))).collect();
    for _ in 0..keys {
        let coeffs: Vec<Scalar> = (0..t).map(|_| Scalar::random(&mut *rng)).collect();
        commitments.push(coeffs.iter().map(|a| ProjectivePoint::GENERATOR * a).collect());
        for (j, v) in shares.iter_mut() {
            v.push(eval_poly(&coeffs, *j));
        }
    }
    Ok(Deal { commitments, shares })
}

/// Check that a dealer's commitments have the right shape: `keys` keys, t points each, and a
/// non-identity constant term.
pub fn check_commitments(commitments: &[Vec<ProjectivePoint>], t: u16, keys: usize) -> bool {
    commitments.len() == keys
        && commitments.iter().all(|c| c.len() == t as usize && c[0] != ProjectivePoint::IDENTITY)
}

/// Check the shares guardian `j` received from one dealer against that dealer's commitments.
pub fn check_shares(commitments: &[Vec<ProjectivePoint>], j: Idx, shares: &[Scalar]) -> bool {
    commitments.len() == shares.len()
        && commitments
            .iter()
            .zip(shares)
            .all(|(c, s)| ProjectivePoint::GENERATOR * s == eval_commitments(c, j))
}

/// The outcome of a ceremony, from one guardian's point of view.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// This guardian's share of each key.
    pub shares: Vec<Scalar>,
    /// Each mint public key.
    pub keys: Vec<ProjectivePoint>,
    /// Every guardian's public share of each key.
    pub public_shares: BTreeMap<Idx, Vec<ProjectivePoint>>,
}

/// The public results (keys and public shares) from every dealer's commitments.
pub fn public_outcome(
    commitments: &BTreeMap<Idx, Vec<Vec<ProjectivePoint>>>,
    n: u16,
) -> (Vec<ProjectivePoint>, BTreeMap<Idx, Vec<ProjectivePoint>>) {
    let keys_len = commitments.values().next().map_or(0, Vec::len);
    let keys = (0..keys_len)
        .map(|k| commitments.values().fold(ProjectivePoint::IDENTITY, |acc, c| acc + c[k][0]))
        .collect();
    let public_shares = (1..=n)
        .map(|j| {
            let v = (0..keys_len)
                .map(|k| commitments.values().fold(ProjectivePoint::IDENTITY, |acc, c| acc + eval_commitments(&c[k], j)))
                .collect();
            (j, v)
        })
        .collect();
    (keys, public_shares)
}

/// Guardian `j` finishes: checks every dealer's commitments and shares (`received[d]` is what
/// dealer `d` sent to `j`), then sums. All n dealers must take part. On a bad dealer, returns
/// [`Error::BadShare`] naming it.
pub fn finish(
    j: Idx,
    t: u16,
    n: u16,
    keys: usize,
    commitments: &BTreeMap<Idx, Vec<Vec<ProjectivePoint>>>,
    received: &BTreeMap<Idx, Vec<Scalar>>,
) -> Result<Outcome, Error> {
    for d in 1..=n {
        let c = commitments.get(&d).ok_or(Error::MissingShare(d))?;
        let s = received.get(&d).ok_or(Error::MissingShare(d))?;
        if !check_commitments(c, t, keys) || !check_shares(c, j, s) {
            return Err(Error::BadShare(d));
        }
    }
    if commitments.len() != n as usize || received.len() != n as usize {
        return Err(Error::InvalidSignerSet);
    }
    let shares = (0..keys).map(|k| received.values().fold(Scalar::ZERO, |acc, s| acc + s[k])).collect();
    let (keys_pub, public_shares) = public_outcome(commitments, n);
    let out = Outcome { shares, keys: keys_pub, public_shares };
    // Self-check: our summed shares match our public share.
    for (k, s) in out.shares.iter().enumerate() {
        if ProjectivePoint::GENERATOR * s != out.public_shares[&j][k] {
            return Err(Error::CombinedInvalid);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir;
    use rand_core::OsRng;

    fn ceremony(t: u16, n: u16, keys: usize) -> BTreeMap<Idx, Outcome> {
        let deals: BTreeMap<Idx, Deal> = (1..=n).map(|d| (d, deal(t, n, keys, &mut OsRng).unwrap())).collect();
        let commitments: BTreeMap<_, _> = deals.iter().map(|(d, x)| (*d, x.commitments.clone())).collect();
        (1..=n)
            .map(|j| {
                let received = deals.iter().map(|(d, x)| (*d, x.shares[&j].clone())).collect();
                (j, finish(j, t, n, keys, &commitments, &received).unwrap())
            })
            .collect()
    }

    #[test]
    fn any_t_shares_reconstruct_the_public_key() {
        let out = ceremony(2, 3, 4);
        // everyone agrees on the public results
        assert!(out.values().all(|o| o.keys == out[&1].keys && o.public_shares == out[&1].public_shares));
        for k in 0..4 {
            for set in [[1u16, 2], [2, 3], [1, 3]] {
                let parts: Vec<_> = set.iter().map(|j| (*j, out[j].shares[k])).collect();
                let key = shamir::combine_scalars(&parts).unwrap();
                assert_eq!(ProjectivePoint::GENERATOR * key, out[&1].keys[k]);
            }
        }
    }

    #[test]
    fn a_bad_share_names_its_dealer() {
        let (t, n, keys) = (2, 3, 2);
        let mut deals: BTreeMap<Idx, Deal> = (1..=n).map(|d| (d, deal(t, n, keys, &mut OsRng).unwrap())).collect();
        deals.get_mut(&2).unwrap().shares.get_mut(&1).unwrap()[1] += Scalar::ONE;
        let commitments: BTreeMap<_, _> = deals.iter().map(|(d, x)| (*d, x.commitments.clone())).collect();
        let received = deals.iter().map(|(d, x)| (*d, x.shares[&1].clone())).collect();
        assert_eq!(finish(1, t, n, keys, &commitments, &received).unwrap_err(), Error::BadShare(2));
        // a missing dealer is caught too (with the bad share undone)
        deals.get_mut(&2).unwrap().shares.get_mut(&1).unwrap()[1] -= Scalar::ONE;
        let mut partial = commitments.clone();
        partial.remove(&3);
        let received: BTreeMap<_, _> = deals.iter().map(|(d, x)| (*d, x.shares[&1].clone())).collect();
        assert_eq!(finish(1, t, n, keys, &partial, &received).unwrap_err(), Error::MissingShare(3));
    }
}
