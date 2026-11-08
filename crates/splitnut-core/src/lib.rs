//! SplitNut core: threshold maths for Cashu mint keys.
//!
//! Every mint operation is "multiply a point by the secret key k", which is linear in k,
//! so Shamir shares of k combine with Lagrange coefficients:
//!
//! * blind signing: `C' = Σ λ_i · (k_i · B')`, see [`sign`]
//! * NUT-12 DLEQ: per-guardian nonces in two rounds, combined the same way, see [`sign`]
//! * proof checking: `C = Σ λ_i · (k_i · Y)` with `Y = hash_to_curve(secret)`, see [`verify`]
//!
//! Hashing (`hash_to_curve`, the NUT-12 challenge) always goes through the `cashu` crate;
//! scalar and point arithmetic uses `k256`, converting at the edges via 33-byte SEC1 points
//! ([`conv`]).
//!
//! Everything here is synchronous and transport-free, so the same code runs with in-memory
//! guardians (milestone 2) and with guardians over Marmot (milestone 3).

#![forbid(unsafe_code)]

pub mod conv;
pub mod error;
pub mod shamir;
pub mod sign;
pub mod verify;

pub use error::Error;
pub use k256::{ProjectivePoint, Scalar};

/// A guardian's share index: the x-coordinate of its point on the Shamir polynomial (1..=n).
pub type Idx = u16;
