//! SplitNut wire messages inside the Marmot group (JSON, carried as MLS application messages).
//!
//! The coordinator sends [`Request`]s addressed to one guardian (`to`); the guardian answers
//! with a [`Response`] carrying its own index (`from`). Receivers check `from` against the
//! sender's authenticated Nostr key, which MDK binds to the MLS credential, so a guardian
//! cannot answer on behalf of another. Guardians accept requests only from the pinned
//! coordinator key.
//!
//! Points are 33-byte compressed hex, scalars 32-byte hex.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use splitnut_core::guardian::{RequestId, SignItem};
use splitnut_core::keyfile::{point_hex, scalar_hex, to_hex_point, to_hex_scalar};
use splitnut_core::sign::Round1;
use splitnut_core::verify::Partial;
use splitnut_core::{Error, Idx, Scalar};

pub const VERSION: u8 = 1;

/// Nostr kind of a guardian's public ledger event (NIP-78 application data, replaceable).
pub const LEDGER_KIND: u16 = 30078;
/// `d` tag prefix of a guardian's ledger event; the keyset id follows.
pub const LEDGER_D_PREFIX: &str = "splitnut-ledger/";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Wire {
    Request(Request),
    Response(Response),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    pub v: u8,
    /// Addressed guardian, or 0 for several (see `targets`).
    pub to: Idx,
    pub req: RequestId,
    pub body: RequestBody,
    /// With `to = 0`: the guardians this is for; absent means all of them. Identical requests
    /// to several guardians travel as one message, to stay within relay rate limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<Idx>>,
}

impl Request {
    pub fn is_for(&self, index: Idx) -> bool {
        self.to == index || (self.to == 0 && self.targets.as_ref().is_none_or(|t| t.contains(&index)))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RequestBody {
    /// Round 1 of threshold signing. `context` says what the outputs are for; a guardian
    /// releases its share only if the operation checks out (see [`WireOp`]).
    Sign1 {
        keyset: String,
        items: Vec<WireSignItem>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context: Option<WireOp>,
    },
    /// Round 2: one challenge per item, same items and order as round 1.
    Sign2 { keyset: String, items: Vec<WireSignItem>, es: Vec<String> },
    /// Drop the nonces of a request that will not reach round 2.
    Abort,
    /// Partial evaluations for proof checks; the guardian computes `Y` from each secret.
    /// `context` (with no inputs: the items are the inputs) lets a guardian refuse proofs
    /// already spent by another operation, and record a melt's spends.
    Verify {
        keyset: String,
        items: Vec<WireVerifyItem>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context: Option<WireOp>,
    },
    /// Liveness check; answered with status and ledger totals.
    Ping,
    /// Broadcast (`to = 0`) after a successful signature: the finished signatures, so every
    /// guardian can check each DLEQ and count the issuance, signer or not. With `context`, the
    /// operation's inputs (with evidence) too, so every guardian records the spends; after a
    /// melt's proof check this is sent with no outputs. No reply.
    Issued {
        keyset: String,
        outputs: Vec<WireIssued>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context: Option<WireOp>,
    },
    /// Key generation, step 1: deal shares for one key per amount. Answered with `DkgDeal`.
    DkgStart { session: String, t: u16, n: u16, unit: String, input_fee_ppk: u64, amounts: Vec<u64> },
    /// Key generation, step 2: every dealer's commitments, and the shares dealt to the addressed
    /// guardian (NIP-44 ciphertext from each other dealer), as `(dealer, …)` pairs. Answered
    /// with `DkgDone`. (Pairs, not maps: serde cannot read integer map keys back inside an
    /// internally tagged enum.)
    DkgDeals {
        session: String,
        commitments: Vec<(Idx, Vec<Vec<String>>)>,
        shares: Vec<(Idx, String)>,
    },
}

/// One finished blind signature, as returned to the mint.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireIssued {
    pub amount: u64,
    pub b: String,
    pub c: String,
    pub e: String,
    pub s: String,
}

/// What a signature or proof check is for, as passed down from cdk-mintd (CDK's
/// `OperationContext`). Inputs carry evidence that they are validly signed, so a guardian can
/// check them without trusting the coordinator or the mint host.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum WireOp {
    /// Issuing ecash for paid mint quotes.
    Mint { quotes: Vec<WireQuote> },
    /// Swapping inputs for outputs.
    Swap { inputs: Vec<WireInput> },
    /// Melting inputs to pay `request`; signing covers the change.
    Melt { quote_id: String, amount: u64, request: String, inputs: Vec<WireInput> },
}

impl WireOp {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Mint { .. } => "mint",
            Self::Swap { .. } => "swap",
            Self::Melt { .. } => "melt",
        }
    }

    pub fn inputs(&self) -> &[WireInput] {
        match self {
            Self::Mint { .. } => &[],
            Self::Swap { inputs } | Self::Melt { inputs, .. } => inputs,
        }
    }

    /// The same operation without its inputs (for proof-check requests, where the items are
    /// the inputs).
    pub fn without_inputs(&self) -> Self {
        match self {
            Self::Mint { quotes } => Self::Mint { quotes: quotes.clone() },
            Self::Swap { .. } => Self::Swap { inputs: vec![] },
            Self::Melt { quote_id, amount, request, .. } => {
                Self::Melt { quote_id: quote_id.clone(), amount: *amount, request: request.clone(), inputs: vec![] }
            }
        }
    }
}

/// A mint quote an issuance draws on. `amount_paid` and `amount_issued` are the mint host's
/// claims; a guardian keeps its own count of what it issued against each quote.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireQuote {
    pub id: String,
    pub amount_paid: u64,
    pub amount_issued: u64,
    pub request: String,
}

/// An input proof with the partial evaluations of t guardians, each with its DLEQ. Anyone
/// holding the public shares can check that they combine to `C`, so the proof is validly
/// signed by the mint key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireInput {
    pub amount: u64,
    pub secret: String,
    pub c: String,
    pub evidence: Vec<WireEvidence>,
}

/// Guardian `i`'s partial evaluation on an input, as returned by a proof check.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireEvidence {
    pub i: Idx,
    #[serde(flatten)]
    pub partial: WirePartial,
}

/// A guardian's ledger totals, reported in heartbeat replies.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireLedger {
    pub issued: u64,
    pub redeemed: u64,
    pub outstanding: i64,
    pub signed_last_hour: u64,
    pub cap_per_hour: u64,
    pub duplicates: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireSignItem {
    pub amount: u64,
    /// Blinded message `B'`.
    pub b: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireVerifyItem {
    pub amount: u64,
    /// The proof's secret (as in the token); `Y = hash_to_curve(secret)`.
    pub secret: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    pub v: u8,
    pub from: Idx,
    pub req: RequestId,
    pub body: ResponseBody,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseBody {
    /// `approved`: digest of the operation this guardian approved (see [`approval_digest`]).
    /// Every group member sees this reply, so other guardians learn of the approval, and the
    /// spends in it, directly from this guardian rather than from the coordinator.
    Sign1 {
        parts: Vec<WireRound1>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approved: Option<String>,
    },
    Sign2 { s: Vec<String> },
    Verify {
        partials: Vec<WirePartial>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approved: Option<String>,
    },
    Pong {
        pending: usize,
        #[serde(default)]
        ledger: Option<WireLedger>,
    },
    /// Per key, commitments to the dealer's t coefficients (points); per other guardian, its
    /// shares NIP-44-encrypted from this guardian's Nostr key to that guardian's.
    DkgDeal { session: String, commitments: Vec<Vec<String>>, shares: Vec<(Idx, String)> },
    /// The ceremony checked out: the resulting keyset, and a hash of the whole public keyset
    /// so the coordinator can confirm every guardian computed the same one.
    DkgDone { session: String, keyset_id: String, keyset_hash: String },
    Error { msg: String },
}

impl ResponseBody {
    /// Which request kind this answers (for matching replies to waiters).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Sign1 { .. } => "sign1",
            Self::Sign2 { .. } => "sign2",
            Self::Verify { .. } => "verify",
            Self::Pong { .. } => "ping",
            Self::DkgDeal { .. } => "dkg_start",
            Self::DkgDone { .. } => "dkg_deals",
            Self::Error { .. } => "error",
        }
    }
}

impl RequestBody {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Sign1 { .. } => "sign1",
            Self::Sign2 { .. } => "sign2",
            Self::Abort => "abort",
            Self::Verify { .. } => "verify",
            Self::Ping => "ping",
            Self::Issued { .. } => "issued",
            Self::DkgStart { .. } => "dkg_start",
            Self::DkgDeals { .. } => "dkg_deals",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireRound1 {
    pub c: String,
    pub r1: String,
    pub r2: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WirePartial {
    pub y_i: String,
    pub e: String,
    pub s: String,
}

/// Digest binding an approval to exactly what was approved: the request kind, its items and its
/// operation context. A guardian puts it in its reply; others match it against the request
/// they saw.
pub fn approval_digest(kind: &str, items: &impl Serialize, context: &WireOp) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(&(kind, items, context)).expect("wire types serialise");
    hex::encode(Sha256::digest(bytes))
}

impl Wire {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("wire types serialise")
    }

    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

// ---- conversions between wire and core types ----

pub fn sign_items_to_wire(items: &[SignItem]) -> Result<Vec<WireSignItem>, Error> {
    items.iter().map(|it| Ok(WireSignItem { amount: it.amount, b: to_hex_point(&it.b)? })).collect()
}

pub fn sign_items_from_wire(items: &[WireSignItem]) -> Result<Vec<SignItem>, Error> {
    items.iter().map(|it| Ok(SignItem { amount: it.amount, b: point_hex(&it.b)? })).collect()
}

pub fn round1_to_wire(r: &Round1) -> Result<WireRound1, Error> {
    Ok(WireRound1 { c: to_hex_point(&r.c)?, r1: to_hex_point(&r.r1)?, r2: to_hex_point(&r.r2)? })
}

pub fn round1_from_wire(r: &WireRound1) -> Result<Round1, Error> {
    Ok(Round1 { c: point_hex(&r.c)?, r1: point_hex(&r.r1)?, r2: point_hex(&r.r2)? })
}

pub fn scalars_to_wire(v: &[Scalar]) -> Vec<String> {
    v.iter().map(to_hex_scalar).collect()
}

pub fn scalars_from_wire(v: &[String]) -> Result<Vec<Scalar>, Error> {
    v.iter().map(|s| scalar_hex(s)).collect()
}

/// Per-key Feldman commitments to hex.
pub fn commitments_to_wire(c: &[Vec<splitnut_core::ProjectivePoint>]) -> Result<Vec<Vec<String>>, Error> {
    c.iter().map(|key| key.iter().map(to_hex_point).collect()).collect()
}

pub fn commitments_from_wire(c: &[Vec<String>]) -> Result<Vec<Vec<splitnut_core::ProjectivePoint>>, Error> {
    c.iter().map(|key| key.iter().map(|p| point_hex(p)).collect()).collect()
}

pub fn partial_to_wire(p: &Partial) -> Result<WirePartial, Error> {
    Ok(WirePartial { y_i: to_hex_point(&p.y_i)?, e: to_hex_scalar(&p.e), s: to_hex_scalar(&p.s) })
}

pub fn partial_from_wire(p: &WirePartial) -> Result<Partial, Error> {
    Ok(Partial { y_i: point_hex(&p.y_i)?, e: scalar_hex(&p.e)?, s: scalar_hex(&p.s)? })
}

#[cfg(test)]
mod tests {
    use super::*;
    use splitnut_core::ProjectivePoint;

    #[test]
    fn roundtrip() {
        let g = ProjectivePoint::GENERATOR;
        let items = vec![SignItem { amount: 8, b: g * Scalar::from(7u64) }];
        let req = Wire::Request(Request {
            v: VERSION,
            to: 2,
            req: 42,
            targets: None,
            body: RequestBody::Sign1 { keyset: "01ab".into(), items: sign_items_to_wire(&items).unwrap(), context: None },
        });
        let json = req.to_json();
        assert!(json.contains("\"type\":\"sign1\""));
        assert_eq!(Wire::from_json(&json).unwrap(), req);
        // DKG messages carry per-guardian lists; they must survive the internally tagged enums.
        let deals = Wire::Request(Request {
            v: VERSION,
            to: 1,
            req: 7,
            targets: None,
            body: RequestBody::DkgDeals {
                session: "s".into(),
                commitments: vec![(2, vec![vec!["02ab".into()]])],
                shares: vec![(2, "cipher".into())],
            },
        });
        assert_eq!(Wire::from_json(&deals.to_json()).unwrap(), deals);
        let deal = Wire::Response(Response {
            v: VERSION,
            from: 2,
            req: 7,
            body: ResponseBody::DkgDeal { session: "s".into(), commitments: vec![], shares: vec![(1, "c".into()), (3, "d".into())] },
        });
        assert_eq!(Wire::from_json(&deal.to_json()).unwrap(), deal);
        let r1 = Round1 { c: g, r1: g * Scalar::from(2u64), r2: g * Scalar::from(3u64) };
        assert_eq!(round1_from_wire(&round1_to_wire(&r1).unwrap()).unwrap(), r1);
    }
}
