use crate::Idx;

/// Errors from the threshold maths.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid threshold: t={t}, n={n}")]
    InvalidThreshold { t: u16, n: u16 },
    #[error("signer set is empty or has duplicate indices")]
    InvalidSignerSet,
    #[error("need {need} shares, got {got}")]
    NotEnoughShares { need: usize, got: usize },
    #[error("missing share from guardian {0}")]
    MissingShare(Idx),
    #[error("no public share known for guardian {0}")]
    UnknownGuardian(Idx),
    #[error("guardian {0} returned an invalid share")]
    BadShare(Idx),
    #[error("invalid curve point")]
    InvalidPoint,
    #[error("invalid scalar")]
    InvalidScalar,
    #[error("combined result is the point at infinity")]
    Infinity,
    #[error("hash to curve failed")]
    HashToCurve,
    #[error("combined signature does not verify")]
    CombinedInvalid,
    #[error("proof signature does not match the mint key")]
    InvalidProof,
}
