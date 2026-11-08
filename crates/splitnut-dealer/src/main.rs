//! splitnut-dealer: run once at setup.
//!
//! Generates one secret key per amount (1 to 2^31 sat by default, matching cdk-mintd's
//! default unit config so the mint never asks for a rotation), splits each t-of-n,
//! writes one share file per guardian, and writes the public keyset (V2 keyset id)
//! plus each guardian's public shares for the coordinator.
//!
//! Trusted dealer for the hackathon; delete its output after distribution.

fn main() {
    println!("splitnut-dealer: not implemented yet (milestone 2)");
}
