//! Conversions between `cashu` key types (libsecp256k1) and `k256` scalars and points.

use cashu::nuts::nut01::{PublicKey, SecretKey};
use k256::elliptic_curve::group::{Group, GroupEncoding};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar};

use crate::Error;

/// cashu `PublicKey` to k256 point.
pub fn point(pk: &PublicKey) -> Result<ProjectivePoint, Error> {
    point_from_bytes(&pk.to_bytes())
}

/// 33-byte compressed SEC1 to k256 point (rejects infinity).
pub fn point_from_bytes(bytes: &[u8]) -> Result<ProjectivePoint, Error> {
    let arr: [u8; 33] = bytes.try_into().map_err(|_| Error::InvalidPoint)?;
    let affine: Option<AffinePoint> =
        AffinePoint::from_bytes(&arr.into()).into();
    affine.map(ProjectivePoint::from).ok_or(Error::InvalidPoint)
}

/// k256 point to 33-byte compressed SEC1 (fails on infinity).
pub fn point_to_bytes(p: &ProjectivePoint) -> Result<[u8; 33], Error> {
    if bool::from(p.is_identity()) {
        return Err(Error::Infinity);
    }
    let enc = p.to_affine().to_encoded_point(true);
    enc.as_bytes().try_into().map_err(|_| Error::InvalidPoint)
}

/// k256 point to cashu `PublicKey`.
pub fn public_key(p: &ProjectivePoint) -> Result<PublicKey, Error> {
    PublicKey::from_slice(&point_to_bytes(p)?).map_err(|_| Error::InvalidPoint)
}

/// 32-byte big-endian to scalar, rejecting values >= n.
pub fn scalar_from_bytes(bytes: &[u8]) -> Result<Scalar, Error> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidScalar)?;
    Option::<Scalar>::from(Scalar::from_repr(arr.into())).ok_or(Error::InvalidScalar)
}

pub fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_repr().into()
}

/// k256 scalar to cashu `SecretKey` (fails on zero).
pub fn secret_key(s: &Scalar) -> Result<SecretKey, Error> {
    SecretKey::from_slice(&scalar_to_bytes(s)).map_err(|_| Error::InvalidScalar)
}

/// cashu `SecretKey` to k256 scalar.
pub fn scalar(sk: &SecretKey) -> Result<Scalar, Error> {
    scalar_from_bytes(sk.as_secret_bytes())
}

/// A DLEQ challenge `e = hash_e(points…)`, computed by the `cashu` crate. With
/// `[R1, R2, K, C']` this is exactly the NUT-12 challenge.
///
/// Returns the scalar and the raw hash bytes: NUT-12 verifiers compare the raw bytes, so a
/// hash >= n (probability ~2^-128) is rejected rather than reduced.
pub fn challenge(points: &[&ProjectivePoint]) -> Result<(Scalar, [u8; 32]), Error> {
    let pks = points
        .iter()
        .map(|p| public_key(p))
        .collect::<Result<Vec<_>, _>>()?;
    let e_bytes = cashu::dhke::hash_e(pks);
    Ok((scalar_from_bytes(&e_bytes)?, e_bytes))
}

/// `Y = hash_to_curve(secret)` via the `cashu` crate.
pub fn hash_to_curve(secret: &[u8]) -> Result<ProjectivePoint, Error> {
    let y = cashu::dhke::hash_to_curve(secret).map_err(|_| Error::HashToCurve)?;
    point(&y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_keys() {
        let sk = SecretKey::generate();
        let s = scalar(&sk).unwrap();
        assert_eq!(secret_key(&s).unwrap(), sk);
        let p = ProjectivePoint::GENERATOR * s;
        assert_eq!(public_key(&p).unwrap(), sk.public_key());
        assert_eq!(point(&sk.public_key()).unwrap(), p);
    }

    #[test]
    fn infinity_rejected() {
        assert_eq!(point_to_bytes(&ProjectivePoint::IDENTITY), Err(Error::Infinity));
    }
}
