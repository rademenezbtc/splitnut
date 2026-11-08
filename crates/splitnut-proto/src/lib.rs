//! SplitNut wire messages exchanged inside the Marmot group (serde JSON).
//!
//! Coordinator to guardians: sign round 1 / round 2 and verify requests, each carrying a
//! request id, the signer set S and the batch of blinded messages or proofs.
//! Guardians to coordinator: partial points, nonce commitments and DLEQ responses.
//!
//! Every message names its sender, and receivers check that against the pinned Nostr key
//! and MLS leaf of that guardian (lesson carried over from BlackIce).

#![forbid(unsafe_code)]
