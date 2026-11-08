//! SplitNut core: threshold maths for Cashu mint keys.
//!
//! Every mint operation is "multiply a point by the secret key k", which is linear in k,
//! so Shamir shares of k combine with Lagrange coefficients:
//!
//! * blind signing: `C' = Σ λ_i · (k_i · B')`
//! * proof checking: `C  = Σ λ_i · (k_i · Y)` with `Y = hash_to_curve(secret)`
//! * NUT-12 DLEQ: two rounds of per-guardian nonces, combined the same way
//!
//! Hashing (`hash_to_curve`, the NUT-12 challenge) always goes through the `cashu` crate;
//! scalar and point arithmetic uses `k256`, converting at the edges via 33-byte SEC1 points.
//!
//! Milestone 2 fills this in: shares, Lagrange, round logic and unit tests.

#![forbid(unsafe_code)]
