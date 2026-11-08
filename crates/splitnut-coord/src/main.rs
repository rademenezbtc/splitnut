//! splitnut-coord: the remote signer that cdk-mintd talks to.
//!
//! Implements CDK's `cdk_signatory::signatory::Signatory` trait and serves it with CDK's own
//! generic `cdk_signatory::start_grpc_server`, so the gRPC schema, TLS and version check are
//! exactly the ones cdk-mintd expects. Each `blind_sign` / `verify_proofs` call fans out to
//! guardians over Marmot; shares are checked against the guardians' public shares before
//! combining. Holds no key material. `rotate_keyset` is refused: the dealer's keyset is
//! the only one.

fn main() {
    println!("splitnut-coord: not implemented yet (milestone 2)");
}
