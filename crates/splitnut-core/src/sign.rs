//! Threshold blind signing with a standard NUT-12 DLEQ proof, in two rounds.
//!
//! For one blinded message `B'` under mint key `k` (public `K = k·G`), signer set `S` of t
//! guardians, `λ_i` the Lagrange coefficients at 0 for `S`:
//!
//! 1. Round 1, guardian `i`: fresh random nonce `r_i`; returns
//!    `C'_i = k_i·B'`, `R1_i = r_i·G`, `R2_i = r_i·B'`.
//! 2. Coordinator: `C' = Σλ_i C'_i`, `R1 = Σλ_i R1_i`, `R2 = Σλ_i R2_i`,
//!    `e = hash_e(R1, R2, K, C')`.
//! 3. Round 2, guardian `i`: `s_i = r_i + e·k_i`.
//! 4. Coordinator checks every share, `s_i·G = R1_i + e·K_i` and `s_i·B' = R2_i + e·C'_i`,
//!    then `s = Σλ_i s_i`.
//!
//! Since `Σλ_i r_i =: r` and `Σλ_i k_i = k`, `(C', e, s)` is an ordinary NUT-12 proof with
//! `R1 = r·G`, `R2 = r·B'`, `s = r + e·k`. Any wallet verifies it against `K` unchanged.
//!
//! Rules: a nonce is used once (round 2 consumes it), and `S` stays fixed across both rounds.
//! If a guardian drops between rounds, restart with fresh nonces.

use std::collections::BTreeMap;

use cashu::nuts::nut00::BlindSignature;
use cashu::nuts::nut01::PublicKey;
use cashu::nuts::nut02::Id;
use cashu::nuts::nut12::BlindSignatureDleq;
use cashu::Amount;
use k256::elliptic_curve::Field;
use k256::{ProjectivePoint, Scalar};
use rand_core::CryptoRngCore;

use crate::{conv, shamir, Error, Idx};

/// A guardian's secret round-1 nonce. Not `Clone`: [`round2`] consumes it.
pub struct Nonce(Scalar);

/// A guardian's round-1 output for one blinded message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Round1 {
    /// `C'_i = k_i·B'`
    pub c: ProjectivePoint,
    /// `R1_i = r_i·G`
    pub r1: ProjectivePoint,
    /// `R2_i = r_i·B'`
    pub r2: ProjectivePoint,
}

/// Guardian, round 1.
pub fn round1(k_i: &Scalar, b: &ProjectivePoint, rng: &mut impl CryptoRngCore) -> (Nonce, Round1) {
    let r = Scalar::random(rng);
    let out = Round1 {
        c: *b * k_i,
        r1: ProjectivePoint::GENERATOR * r,
        r2: *b * r,
    };
    (Nonce(r), out)
}

/// Guardian, round 2: `s_i = r_i + e·k_i`.
pub fn round2(nonce: Nonce, k_i: &Scalar, e: &Scalar) -> Scalar {
    nonce.0 + *e * k_i
}

/// Coordinator state for one blinded message, between round 1 and round 2.
#[derive(Clone, Debug)]
pub struct Session {
    k_pub: ProjectivePoint,
    b: ProjectivePoint,
    parts: Vec<(Idx, Round1)>,
    c: ProjectivePoint,
    e: Scalar,
}

impl Session {
    /// Combine round-1 outputs from the signer set and compute the NUT-12 challenge.
    pub fn new(
        k_pub: ProjectivePoint,
        b: ProjectivePoint,
        parts: Vec<(Idx, Round1)>,
    ) -> Result<Self, Error> {
        let set: Vec<Idx> = parts.iter().map(|(i, _)| *i).collect();
        shamir::check_set(&set)?;
        let pick = |f: fn(&Round1) -> ProjectivePoint| -> Vec<(Idx, ProjectivePoint)> {
            parts.iter().map(|(i, r)| (*i, f(r))).collect()
        };
        let c = shamir::combine_points(&pick(|r| r.c))?;
        let r1 = shamir::combine_points(&pick(|r| r.r1))?;
        let r2 = shamir::combine_points(&pick(|r| r.r2))?;
        let (e, _) = conv::challenge(&[&r1, &r2, &k_pub, &c])?;
        Ok(Self { k_pub, b, parts, c, e })
    }

    /// The signer set, fixed for round 2.
    pub fn signers(&self) -> Vec<Idx> {
        self.parts.iter().map(|(i, _)| *i).collect()
    }

    /// The challenge every signer needs for round 2.
    pub fn challenge(&self) -> Scalar {
        self.e
    }

    /// Check each guardian's round-2 share against its public share `K_i`, then combine.
    /// Returns `(C', e, s)`. A cheating guardian is named in [`Error::BadShare`].
    pub fn finish(
        self,
        public_shares: &BTreeMap<Idx, ProjectivePoint>,
        s_parts: &[(Idx, Scalar)],
    ) -> Result<(ProjectivePoint, Scalar, Scalar), Error> {
        let s_map: BTreeMap<Idx, Scalar> = s_parts.iter().copied().collect();
        let mut ordered = Vec::with_capacity(self.parts.len());
        for (i, r) in &self.parts {
            let s_i = *s_map.get(i).ok_or(Error::MissingShare(*i))?;
            let k_i = public_shares.get(i).ok_or(Error::UnknownGuardian(*i))?;
            let ok_g = ProjectivePoint::GENERATOR * s_i == r.r1 + *k_i * self.e;
            let ok_b = self.b * s_i == r.r2 + r.c * self.e;
            if !(ok_g && ok_b) {
                return Err(Error::BadShare(*i));
            }
            ordered.push((*i, s_i));
        }
        let s = shamir::combine_scalars(&ordered)?;
        Ok((self.c, self.e, s))
    }

    /// The mint public key this session signs under.
    pub fn mint_key(&self) -> ProjectivePoint {
        self.k_pub
    }
}

/// Build a cashu `BlindSignature` from a finished session, and check it with the `cashu`
/// crate's own NUT-12 verification before returning it.
pub fn blind_signature(
    amount: Amount,
    keyset_id: Id,
    blinded_message: &PublicKey,
    mint_key: &ProjectivePoint,
    (c, e, s): (ProjectivePoint, Scalar, Scalar),
) -> Result<BlindSignature, Error> {
    let sig = BlindSignature {
        amount,
        keyset_id,
        c: conv::public_key(&c)?,
        dleq: Some(BlindSignatureDleq {
            e: conv::secret_key(&e)?,
            s: conv::secret_key(&s)?,
        }),
    };
    sig.verify_dleq(conv::public_key(mint_key)?, *blinded_message)
        .map_err(|_| Error::CombinedInvalid)?;
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cashu::dhke;
    use cashu::nuts::nut01::SecretKey;
    use cashu::secret::Secret;
    use rand_core::OsRng;

    struct Dealt {
        k: Scalar,
        k_pub: ProjectivePoint,
        shares: BTreeMap<Idx, Scalar>,
        public_shares: BTreeMap<Idx, ProjectivePoint>,
    }

    fn deal(t: u16, n: u16) -> Dealt {
        let k = Scalar::random(&mut OsRng);
        let shares: BTreeMap<_, _> = shamir::split(&k, t, n, &mut OsRng).unwrap().into_iter().collect();
        let public_shares = shares.iter().map(|(i, s)| (*i, ProjectivePoint::GENERATOR * s)).collect();
        Dealt { k, k_pub: ProjectivePoint::GENERATOR * k, shares, public_shares }
    }

    /// Run both rounds for signer set `set`; `cheat` lets one guardian tamper with its s_i.
    fn threshold_sign(d: &Dealt, set: &[Idx], b: &ProjectivePoint, cheat: Option<Idx>) -> Result<(ProjectivePoint, Scalar, Scalar), Error> {
        let mut nonces = BTreeMap::new();
        let mut r1s = vec![];
        for i in set {
            let (nonce, out) = round1(&d.shares[i], b, &mut OsRng);
            nonces.insert(*i, nonce);
            r1s.push((*i, out));
        }
        let session = Session::new(d.k_pub, *b, r1s)?;
        let e = session.challenge();
        let s_parts: Vec<_> = set
            .iter()
            .map(|i| {
                let mut s = round2(nonces.remove(i).unwrap(), &d.shares[i], &e);
                if cheat == Some(*i) {
                    s += Scalar::ONE;
                }
                (*i, s)
            })
            .collect();
        session.finish(&d.public_shares, &s_parts)
    }

    #[test]
    fn threshold_signature_is_standard_cashu() {
        let d = deal(2, 3);
        let mint_sk = conv::secret_key(&d.k).unwrap();
        let keyset_id = Id::from_bytes(&[0u8; 8]).unwrap();
        for set in [[1, 2], [1, 3], [2, 3], [3, 1]] {
            // wallet side, via the cashu crate
            let secret = Secret::generate();
            let (b_pk, r) = dhke::blind_message(secret.as_bytes(), None).unwrap();
            let b = conv::point(&b_pk).unwrap();

            let out = threshold_sign(&d, &set, &b, None).unwrap();
            // C' equals what the single-key mint would produce
            assert_eq!(conv::public_key(&out.0).unwrap(), dhke::sign_message(&mint_sk, &b_pk).unwrap());

            // DLEQ verifies with the cashu crate's own check (inside blind_signature)
            let sig = blind_signature(Amount::from(8), keyset_id, &b_pk, &d.k_pub, out).unwrap();

            // and the unblinded token verifies against the full key
            let c = dhke::unblind_message(&sig.c, &r, &mint_sk.public_key()).unwrap();
            dhke::verify_message(&mint_sk, c, secret.as_bytes()).unwrap();
        }
    }

    #[test]
    fn three_of_five() {
        let d = deal(3, 5);
        let b_pk = SecretKey::generate().public_key();
        let b = conv::point(&b_pk).unwrap();
        let out = threshold_sign(&d, &[5, 2, 4], &b, None).unwrap();
        blind_signature(Amount::from(1), Id::from_bytes(&[0u8; 8]).unwrap(), &b_pk, &d.k_pub, out).unwrap();
    }

    #[test]
    fn cheating_guardian_is_named() {
        let d = deal(2, 3);
        let b = conv::point(&SecretKey::generate().public_key()).unwrap();
        assert_eq!(threshold_sign(&d, &[1, 3], &b, Some(3)).unwrap_err(), Error::BadShare(3));
    }

    #[test]
    fn wrong_round1_point_is_caught() {
        // A guardian that returns a bogus C'_i in round 1 fails the s_i·B' check in round 2.
        let d = deal(2, 3);
        let b = conv::point(&SecretKey::generate().public_key()).unwrap();
        let (n1, mut o1) = round1(&d.shares[&1], &b, &mut OsRng);
        let (n2, o2) = round1(&d.shares[&2], &b, &mut OsRng);
        o1.c += ProjectivePoint::GENERATOR;
        let session = Session::new(d.k_pub, b, vec![(1, o1), (2, o2)]).unwrap();
        let e = session.challenge();
        let s = vec![(1, round2(n1, &d.shares[&1], &e)), (2, round2(n2, &d.shares[&2], &e))];
        assert_eq!(session.finish(&d.public_shares, &s).unwrap_err(), Error::BadShare(1));
    }

    #[test]
    fn missing_round2_share() {
        let d = deal(2, 3);
        let b = conv::point(&SecretKey::generate().public_key()).unwrap();
        let (n1, o1) = round1(&d.shares[&1], &b, &mut OsRng);
        let (_n2, o2) = round1(&d.shares[&2], &b, &mut OsRng);
        let session = Session::new(d.k_pub, b, vec![(1, o1), (2, o2)]).unwrap();
        let e = session.challenge();
        let s = vec![(1, round2(n1, &d.shares[&1], &e))];
        assert_eq!(session.finish(&d.public_shares, &s).unwrap_err(), Error::MissingShare(2));
    }
}
