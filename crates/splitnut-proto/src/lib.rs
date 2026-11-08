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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Wire {
    Request(Request),
    Response(Response),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    pub v: u8,
    pub to: Idx,
    pub req: RequestId,
    pub body: RequestBody,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RequestBody {
    /// Round 1 of threshold signing.
    Sign1 { keyset: String, items: Vec<WireSignItem> },
    /// Round 2: one challenge per item, same items and order as round 1.
    Sign2 { keyset: String, items: Vec<WireSignItem>, es: Vec<String> },
    /// Drop the nonces of a request that will not reach round 2.
    Abort,
    /// Partial evaluations for proof checks; the guardian computes `Y` from each secret.
    Verify { keyset: String, items: Vec<WireVerifyItem> },
    /// Liveness check.
    Ping,
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
    Sign1 { parts: Vec<WireRound1> },
    Sign2 { s: Vec<String> },
    Verify { partials: Vec<WirePartial> },
    Pong { pending: usize },
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
            body: RequestBody::Sign1 { keyset: "01ab".into(), items: sign_items_to_wire(&items).unwrap() },
        });
        let json = req.to_json();
        assert!(json.contains("\"type\":\"sign1\""));
        assert_eq!(Wire::from_json(&json).unwrap(), req);
        let r1 = Round1 { c: g, r1: g * Scalar::from(2u64), r2: g * Scalar::from(3u64) };
        assert_eq!(round1_from_wire(&round1_to_wire(&r1).unwrap()).unwrap(), r1);
    }
}
