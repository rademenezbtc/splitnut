//! Threshold proof checking (the signer's `verify_proofs`), one round.
//!
//! For a proof `(amount, secret, C)` the mint must check `C = k·Y` with
//! `Y = hash_to_curve(secret)`. Each guardian `i` in the signer set returns `Y_i = k_i·Y`
//! with a Chaum–Pedersen DLEQ proving `log_G K_i = log_Y Y_i`; the coordinator checks every
//! partial, then `Σλ_i Y_i = C`.
//!
//! The partial DLEQ is SplitNut's own (not NUT-12): challenge
//! `e = hash_e(R1, R2, K_i, Y, Y_i)`, response `s = r + e·k_i`.

use std::collections::BTreeMap;

use k256::elliptic_curve::Field;
use k256::{ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;

use crate::{conv, shamir, Error, Idx};

/// A guardian's partial evaluation `Y_i = k_i·Y` with its DLEQ proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partial {
    pub y_i: ProjectivePoint,
    pub e: Scalar,
    pub s: Scalar,
}

/// Guardian: evaluate its share on `Y` and prove it.
pub fn partial(k_i: &Scalar, y: &ProjectivePoint, rng: &mut impl CryptoRngCore) -> Result<Partial, Error> {
    let k_pub_i = ProjectivePoint::GENERATOR * k_i;
    let y_i = *y * k_i;
    let r = Scalar::random(rng);
    let r1 = ProjectivePoint::GENERATOR * r;
    let r2 = *y * r;
    let (e, _) = conv::challenge(&[&r1, &r2, &k_pub_i, y, &y_i])?;
    Ok(Partial { y_i, e, s: r + e * k_i })
}

/// Coordinator: check one partial against the guardian's public share `K_i`.
pub fn check_partial(k_pub_i: &ProjectivePoint, y: &ProjectivePoint, p: &Partial) -> bool {
    // R1 = s·G − e·K_i, R2 = s·Y − e·Y_i, then recompute e.
    let r1 = ProjectivePoint::GENERATOR * p.s - *k_pub_i * p.e;
    let r2 = *y * p.s - p.y_i * p.e;
    matches!(conv::challenge(&[&r1, &r2, k_pub_i, y, &p.y_i]), Ok((e, _)) if e == p.e)
}

/// Coordinator: check every partial, combine, and compare with the proof's `C`.
pub fn combine_and_check(
    c: &ProjectivePoint,
    y: &ProjectivePoint,
    public_shares: &BTreeMap<Idx, ProjectivePoint>,
    parts: &[(Idx, Partial)],
) -> Result<(), Error> {
    for (i, p) in parts {
        let k_i = public_shares.get(i).ok_or(Error::UnknownGuardian(*i))?;
        if !check_partial(k_i, y, p) {
            return Err(Error::BadShare(*i));
        }
    }
    let combined = shamir::combine_points(&parts.iter().map(|(i, p)| (*i, p.y_i)).collect::<Vec<_>>())?;
    if combined == *c {
        Ok(())
    } else {
        Err(Error::InvalidProof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cashu::dhke;
    use cashu::secret::Secret;
    use rand_core::OsRng;

    #[test]
    fn valid_and_forged_proofs() {
        let k = Scalar::random(&mut OsRng);
        let shares: BTreeMap<_, _> = shamir::split(&k, 2, 3, &mut OsRng).unwrap().into_iter().collect();
        let pubs: BTreeMap<_, _> = shares.iter().map(|(i, s)| (*i, ProjectivePoint::GENERATOR * s)).collect();
        let mint_sk = conv::secret_key(&k).unwrap();

        // a real token, made through the cashu crate with the full key
        let secret = Secret::generate();
        let (b, r) = dhke::blind_message(secret.as_bytes(), None).unwrap();
        let c_blind = dhke::sign_message(&mint_sk, &b).unwrap();
        let c = conv::point(&dhke::unblind_message(&c_blind, &r, &mint_sk.public_key()).unwrap()).unwrap();
        let y = conv::hash_to_curve(secret.as_bytes()).unwrap();

        let parts = |set: &[Idx]| -> Vec<(Idx, Partial)> {
            set.iter().map(|i| (*i, partial(&shares[i], &y, &mut OsRng).unwrap())).collect()
        };
        for set in [[1, 2], [2, 3], [3, 1]] {
            combine_and_check(&c, &y, &pubs, &parts(&set)).unwrap();
        }

        // a forged C is rejected
        let forged = c + ProjectivePoint::GENERATOR;
        assert_eq!(combine_and_check(&forged, &y, &pubs, &parts(&[1, 2])), Err(Error::InvalidProof));

        // a guardian lying about Y_i is named
        let mut bad = parts(&[1, 2]);
        bad[1].1.y_i += ProjectivePoint::GENERATOR;
        assert_eq!(combine_and_check(&c, &y, &pubs, &bad), Err(Error::BadShare(2)));
    }
}
