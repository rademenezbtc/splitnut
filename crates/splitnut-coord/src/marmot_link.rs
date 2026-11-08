//! `GuardianLink` over the Marmot group.
//!
//! One [`Hub`] per coordinator owns the subscription to the group and routes each guardian
//! response to the request waiting for it, keyed by (request id, guardian, kind). Responses
//! are accepted only from roster keys, and only when the claimed `from` index matches the
//! authenticated sender.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use splitnut_core::guardian::{RequestId, SignItem};
use splitnut_core::sign::Round1;
use splitnut_core::verify::Partial;
use splitnut_core::{Idx, Scalar};
use splitnut_marmot::{MarmotNode, NostrPublicKey};
use splitnut_proto::*;
use tokio::sync::oneshot;
use tracing::{debug, warn};

use crate::link::{GuardianLink, LinkError};

type Key = (RequestId, Idx, &'static str);

pub struct Hub {
    node: MarmotNode,
    keyset: String,
    pending: Mutex<HashMap<Key, oneshot::Sender<ResponseBody>>>,
}

impl Hub {
    pub fn start(node: MarmotNode, keyset: String, roster: HashMap<NostrPublicKey, Idx>) -> Arc<Self> {
        let hub = Arc::new(Self { node, keyset, pending: Mutex::new(HashMap::new()) });
        let mut rx = hub.node.subscribe();
        let h = hub.clone();
        tokio::spawn(async move {
            loop {
                let msg = match rx.recv().await {
                    Ok(m) => m,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("hub dropped {n} messages");
                        continue;
                    }
                    Err(_) => break,
                };
                let Some(&idx) = roster.get(&msg.from) else {
                    warn!(from = %msg.from, "message from a key not in the roster");
                    continue;
                };
                let resp = match Wire::from_json(&msg.content) {
                    Ok(Wire::Response(r)) => r,
                    Ok(Wire::Request(_)) => continue,
                    Err(e) => {
                        warn!(guardian = idx, "malformed response: {e}");
                        continue;
                    }
                };
                if resp.from != idx {
                    warn!(guardian = idx, claimed = resp.from, "response claims another guardian's index; dropped");
                    continue;
                }
                // An error answers whatever this guardian was asked for this request.
                let kinds: &[&'static str] = match &resp.body {
                    ResponseBody::Error { .. } => &["sign1", "sign2", "verify", "ping"],
                    b => match b.kind() {
                        "sign1" => &["sign1"],
                        "sign2" => &["sign2"],
                        "verify" => &["verify"],
                        _ => &["ping"],
                    },
                };
                let waiter = {
                    let mut p = h.pending.lock().unwrap();
                    kinds.iter().find_map(|k| p.remove(&(resp.req, idx, *k)))
                };
                match waiter {
                    Some(tx) => {
                        let _ = tx.send(resp.body);
                    }
                    None => debug!(req = resp.req, guardian = idx, "late or unexpected response"),
                }
            }
        });
        hub
    }

    async fn call(&self, to: Idx, req: RequestId, body: RequestBody) -> Result<ResponseBody, LinkError> {
        let kind = body.kind();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert((req, to, kind), tx);
        // Remove the waiter however this future ends (answered, failed, or timed out by the caller).
        struct Cleanup<'a>(&'a Hub, Key);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                self.0.pending.lock().unwrap().remove(&self.1);
            }
        }
        let _cleanup = Cleanup(self, (req, to, kind));

        let wire = Wire::Request(Request { v: VERSION, to, req, body });
        self.node.send(wire.to_json()).await.map_err(|e| LinkError::Refused(to, format!("send: {e}")))?;
        let body = rx.await.map_err(|_| LinkError::Offline(to))?;
        match body {
            ResponseBody::Error { msg } => Err(LinkError::Refused(to, msg)),
            b => Ok(b),
        }
    }

    async fn notify(&self, to: Idx, req: RequestId, body: RequestBody) {
        let wire = Wire::Request(Request { v: VERSION, to, req, body });
        if let Err(e) = self.node.send(wire.to_json()).await {
            debug!(guardian = to, "notify failed: {e}");
        }
    }
}

pub struct MarmotLink {
    index: Idx,
    hub: Arc<Hub>,
}

impl MarmotLink {
    pub fn new(index: Idx, hub: Arc<Hub>) -> Self {
        Self { index, hub }
    }
}

fn bad(i: Idx, e: impl std::fmt::Display) -> LinkError {
    LinkError::Refused(i, format!("bad response: {e}"))
}

#[async_trait]
impl GuardianLink for MarmotLink {
    fn index(&self) -> Idx {
        self.index
    }

    async fn round1(&self, req: RequestId, items: Vec<SignItem>) -> Result<Vec<Round1>, LinkError> {
        let i = self.index;
        let body = RequestBody::Sign1 { keyset: self.hub.keyset.clone(), items: sign_items_to_wire(&items).map_err(|e| bad(i, e))? };
        match self.hub.call(i, req, body).await? {
            ResponseBody::Sign1 { parts } => parts.iter().map(round1_from_wire).collect::<Result<_, _>>().map_err(|e| bad(i, e)),
            other => Err(bad(i, format!("unexpected {}", other.kind()))),
        }
    }

    async fn round2(&self, req: RequestId, items: Vec<SignItem>, es: Vec<Scalar>) -> Result<Vec<Scalar>, LinkError> {
        let i = self.index;
        let body = RequestBody::Sign2 {
            keyset: self.hub.keyset.clone(),
            items: sign_items_to_wire(&items).map_err(|e| bad(i, e))?,
            es: scalars_to_wire(&es),
        };
        match self.hub.call(i, req, body).await? {
            ResponseBody::Sign2 { s } => scalars_from_wire(&s).map_err(|e| bad(i, e)),
            other => Err(bad(i, format!("unexpected {}", other.kind()))),
        }
    }

    async fn abort(&self, req: RequestId) {
        self.hub.notify(self.index, req, RequestBody::Abort).await;
    }

    async fn verify(&self, req: RequestId, items: Vec<(u64, String)>) -> Result<Vec<Partial>, LinkError> {
        let i = self.index;
        let body = RequestBody::Verify {
            keyset: self.hub.keyset.clone(),
            items: items.into_iter().map(|(amount, secret)| WireVerifyItem { amount, secret }).collect(),
        };
        match self.hub.call(i, req, body).await? {
            ResponseBody::Verify { partials } => partials.iter().map(partial_from_wire).collect::<Result<_, _>>().map_err(|e| bad(i, e)),
            other => Err(bad(i, format!("unexpected {}", other.kind()))),
        }
    }
}
