//! Shamir secret sharing over the secp256k1 scalar field, and Lagrange interpolation at 0.

use k256::elliptic_curve::Field;
use k256::{ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;

use crate::{Error, Idx};

/// Split `secret` into `n` shares with threshold `t`: shares are `f(1)..f(n)` for a random
/// polynomial `f` of degree `t-1` with `f(0) = secret`.
pub fn split(
    secret: &Scalar,
    t: u16,
    n: u16,
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<(Idx, Scalar)>, Error> {
    if t == 0 || t > n {
        return Err(Error::InvalidThreshold { t, n });
    }
    let mut coeffs = Vec::with_capacity(t as usize);
    coeffs.push(*secret);
    for _ in 1..t {
        coeffs.push(Scalar::random(&mut *rng));
    }
    Ok((1..=n)
        .map(|i| {
            let x = Scalar::from(u64::from(i));
            // Horner evaluation of f(x)
            let y = coeffs.iter().rev().fold(Scalar::ZERO, |acc, c| acc * x + c);
            (i, y)
        })
        .collect())
}

/// Lagrange coefficient at 0 for guardian `i` within signer set `set`:
/// `λ_i = Π_{j∈set, j≠i} j / (j - i)`.
pub fn lagrange_at_zero(set: &[Idx], i: Idx) -> Result<Scalar, Error> {
    check_set(set)?;
    if !set.contains(&i) {
        return Err(Error::InvalidSignerSet);
    }
    let xi = Scalar::from(u64::from(i));
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &j in set.iter().filter(|&&j| j != i) {
        let xj = Scalar::from(u64::from(j));
        num *= xj;
        den *= xj - xi;
    }
    let inv: Option<Scalar> = den.invert().into();
    Ok(num * inv.ok_or(Error::InvalidSignerSet)?)
}

/// Signer set is non-empty, has no zero index and no duplicates.
pub fn check_set(set: &[Idx]) -> Result<(), Error> {
    let mut sorted = set.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if set.is_empty() || sorted.len() != set.len() || sorted[0] == 0 {
        return Err(Error::InvalidSignerSet);
    }
    Ok(())
}

/// `Σ λ_i · P_i` over the signer set formed by the given indices.
pub fn combine_points(parts: &[(Idx, ProjectivePoint)]) -> Result<ProjectivePoint, Error> {
    let set: Vec<Idx> = parts.iter().map(|(i, _)| *i).collect();
    parts.iter().try_fold(ProjectivePoint::IDENTITY, |acc, (i, p)| {
        Ok(acc + *p * lagrange_at_zero(&set, *i)?)
    })
}

/// `Σ λ_i · s_i` over the signer set formed by the given indices.
pub fn combine_scalars(parts: &[(Idx, Scalar)]) -> Result<Scalar, Error> {
    let set: Vec<Idx> = parts.iter().map(|(i, _)| *i).collect();
    parts.iter().try_fold(Scalar::ZERO, |acc, (i, s)| {
        Ok(acc + *s * lagrange_at_zero(&set, *i)?)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn subsets(n: u16, t: u16) -> Vec<Vec<Idx>> {
        let all: Vec<Idx> = (1..=n).collect();
        let mut out = vec![];
        for mask in 0u32..(1 << n) {
            let s: Vec<Idx> = all.iter().copied().filter(|i| mask & (1 << (i - 1)) != 0).collect();
            if s.len() == t as usize {
                out.push(s);
            }
        }
        out
    }

    #[test]
    fn any_t_of_n_reconstructs() {
        for (t, n) in [(1, 1), (1, 3), (2, 3), (3, 3), (3, 5), (4, 7)] {
            let k = Scalar::random(&mut OsRng);
            let shares = split(&k, t, n, &mut OsRng).unwrap();
            for set in subsets(n, t) {
                let parts: Vec<_> = set.iter().map(|i| shares[(*i - 1) as usize]).collect();
                assert_eq!(combine_scalars(&parts).unwrap(), k, "t={t} n={n} set={set:?}");
                // and in the exponent: Σ λ_i (k_i·P) = k·P
                let p = ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng);
                let pparts: Vec<_> = parts.iter().map(|(i, s)| (*i, p * s)).collect();
                assert_eq!(combine_points(&pparts).unwrap(), p * k);
            }
        }
    }

    #[test]
    fn fewer_than_t_does_not_reconstruct() {
        let k = Scalar::random(&mut OsRng);
        let shares = split(&k, 3, 5, &mut OsRng).unwrap();
        assert_ne!(combine_scalars(&shares[..2]).unwrap(), k);
    }

    #[test]
    fn rejects_bad_parameters() {
        let k = Scalar::ONE;
        assert!(split(&k, 0, 3, &mut OsRng).is_err());
        assert!(split(&k, 4, 3, &mut OsRng).is_err());
        assert!(lagrange_at_zero(&[1, 1], 1).is_err());
        assert!(lagrange_at_zero(&[0, 2], 2).is_err());
        assert!(lagrange_at_zero(&[1, 2], 3).is_err());
    }
}
