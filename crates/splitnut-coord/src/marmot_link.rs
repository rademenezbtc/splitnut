//! `GuardianLink` over the Marmot group.
//!
//! One [`Hub`] per coordinator owns the subscription to the group and routes each guardian
//! response to the request waiting for it, keyed by (request id, guardian, kind). Responses
//! are accepted only from roster keys, and only when the claimed `from` index matches the
//! authenticated sender.
//!
//! Outgoing requests are batched: identical requests queued within a few milliseconds of each
//! other (round 1 to every candidate, a heartbeat to every guardian, ...) go out as one group
//! message with a `targets` list. Relays rate-limit publishers, typically to about one event
//! per second, so this matters on public relays.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use splitnut_core::guardian::{RequestId, SignItem};
use splitnut_core::sign::Round1;
use splitnut_core::verify::Partial;
use splitnut_core::{Idx, Scalar};
use splitnut_marmot::{MarmotNode, NostrPublicKey};
use splitnut_proto::*;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use crate::link::{Announce, GuardianLink, LinkError, PingInfo};

type Key = (RequestId, Idx, &'static str);

pub struct Hub {
    keyset: String,
    pending: Mutex<HashMap<Key, oneshot::Sender<ResponseBody>>>,
    out: mpsc::UnboundedSender<Outgoing>,
}

struct Outgoing {
    to: Idx,
    req: RequestId,
    body: RequestBody,
    sent: Option<oneshot::Sender<Result<(), String>>>,
}

/// Collect requests queued at about the same time and send identical ones as one message.
async fn batch_sender(node: MarmotNode, mut rx: mpsc::UnboundedReceiver<Outgoing>) {
    while let Some(first) = rx.recv().await {
        tokio::time::sleep(Duration::from_millis(5)).await;
        let mut batch = vec![first];
        while let Ok(o) = rx.try_recv() {
            batch.push(o);
        }
        let mut groups: Vec<(RequestId, String, Vec<Outgoing>)> = vec![];
        for o in batch {
            let key = serde_json::to_string(&o.body).unwrap_or_default();
            match groups.iter_mut().find(|(r, k, _)| *r == o.req && *k == key) {
                Some(g) => g.2.push(o),
                None => groups.push((o.req, key, vec![o])),
            }
        }
        for (req, _, items) in groups {
            let mut targets: Vec<Idx> = items.iter().map(|o| o.to).collect();
            targets.sort_unstable();
            targets.dedup();
            let (to, targets) = if targets.contains(&0) {
                (0, None)
            } else if targets.len() == 1 {
                (targets[0], None)
            } else {
                (0, Some(targets))
            };
            let wire = Wire::Request(Request { v: VERSION, to, req, body: items[0].body.clone(), targets });
            let node = node.clone();
            tokio::spawn(async move {
                let r = node.send(wire.to_json()).await.map_err(|e| e.to_string());
                for o in items {
                    if let Some(tx) = o.sent {
                        let _ = tx.send(r.clone());
                    }
                }
            });
        }
    }
}

impl Hub {
    pub fn start(node: MarmotNode, keyset: String, roster: HashMap<NostrPublicKey, Idx>) -> Arc<Self> {
        let (out, out_rx) = mpsc::unbounded_channel();
        let mut rx = node.subscribe();
        tokio::spawn(batch_sender(node, out_rx));
        let hub = Arc::new(Self { keyset, pending: Mutex::new(HashMap::new()), out });
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

        let (sent_tx, sent_rx) = oneshot::channel();
        self.out.send(Outgoing { to, req, body, sent: Some(sent_tx) }).map_err(|_| LinkError::Transport("hub stopped".into()))?;
        match sent_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(LinkError::Transport(e)),
            Err(_) => return Err(LinkError::Transport("hub stopped".into())),
        }
        let body = rx.await.map_err(|_| LinkError::Offline(to))?;
        match body {
            ResponseBody::Error { msg } => Err(LinkError::Refused(to, msg)),
            b => Ok(b),
        }
    }

    async fn notify(&self, to: Idx, req: RequestId, body: RequestBody) {
        if self.out.send(Outgoing { to, req, body, sent: None }).is_err() {
            debug!(guardian = to, "notify failed: hub stopped");
        }
    }
}

#[async_trait]
impl Announce for Hub {
    async fn issued(&self, req: RequestId, outputs: Vec<WireIssued>, context: Option<WireOp>) {
        self.notify(0, req, RequestBody::Issued { keyset: self.keyset.clone(), outputs, context }).await;
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

    async fn round1(&self, req: RequestId, items: Vec<SignItem>, context: Option<WireOp>) -> Result<Vec<Round1>, LinkError> {
        let i = self.index;
        let body = RequestBody::Sign1 {
            keyset: self.hub.keyset.clone(),
            items: sign_items_to_wire(&items).map_err(|e| bad(i, e))?,
            context,
        };
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

    async fn ping(&self, req: RequestId) -> Result<PingInfo, LinkError> {
        match self.hub.call(self.index, req, RequestBody::Ping).await? {
            ResponseBody::Pong { pending, ledger } => Ok(PingInfo { pending, ledger }),
            other => Err(bad(self.index, format!("unexpected {}", other.kind()))),
        }
    }

    async fn verify(&self, req: RequestId, items: Vec<(u64, String)>, context: Option<WireOp>) -> Result<Vec<Partial>, LinkError> {
        let i = self.index;
        let body = RequestBody::Verify {
            keyset: self.hub.keyset.clone(),
            items: items.into_iter().map(|(amount, secret)| WireVerifyItem { amount, secret }).collect(),
            context,
        };
        match self.hub.call(i, req, body).await? {
            ResponseBody::Verify { partials } => partials.iter().map(partial_from_wire).collect::<Result<_, _>>().map_err(|e| bad(i, e)),
            other => Err(bad(i, format!("unexpected {}", other.kind()))),
        }
    }
}
