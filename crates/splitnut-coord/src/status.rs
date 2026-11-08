//! Live status for the dashboard and for fast refusal: guardian heartbeats and an event bus.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};
use splitnut_core::Idx;
use splitnut_proto::WireLedger;
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::link::GuardianLink;

pub fn unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Dashboard events, with a short history for newly connected viewers.
pub struct Events {
    tx: broadcast::Sender<Value>,
    recent: Mutex<VecDeque<Value>>,
}

const RECENT: usize = 100;

impl Events {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { tx: broadcast::channel(512).0, recent: Mutex::new(VecDeque::new()) })
    }

    pub fn emit(&self, mut ev: Value) {
        ev["ts"] = json!(unix_ms());
        let mut r = self.recent.lock().unwrap();
        if r.len() == RECENT {
            r.pop_front();
        }
        r.push_back(ev.clone());
        let _ = self.tx.send(ev);
    }

    pub fn recent(&self) -> Vec<Value> {
        self.recent.lock().unwrap().iter().cloned().collect()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Value> {
        self.tx.subscribe()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct GuardianStatus {
    pub index: Idx,
    /// None until the first heartbeat.
    pub online: Option<bool>,
    pub last_seen_ms: Option<u64>,
    pub rtt_ms: Option<u64>,
    pub pending: usize,
    pub ledger: Option<WireLedger>,
    pub last_error: Option<String>,
}

/// Guardian liveness, fed by heartbeats and by request outcomes.
pub struct Status {
    inner: Mutex<BTreeMap<Idx, GuardianStatus>>,
    events: Arc<Events>,
}

impl Status {
    pub fn new(indices: &[Idx], events: Arc<Events>) -> Arc<Self> {
        let inner = indices
            .iter()
            .map(|i| (*i, GuardianStatus { index: *i, online: None, last_seen_ms: None, rtt_ms: None, pending: 0, ledger: None, last_error: None }))
            .collect();
        Arc::new(Self { inner: Mutex::new(inner), events })
    }

    /// Known to be down (unknown counts as up, so startup does not refuse).
    pub fn is_down(&self, i: Idx) -> bool {
        self.inner.lock().unwrap().get(&i).map(|g| g.online == Some(false)).unwrap_or(false)
    }

    pub fn mark_down(&self, i: Idx, why: &str) {
        let changed = {
            let mut m = self.inner.lock().unwrap();
            let Some(g) = m.get_mut(&i) else { return };
            let changed = g.online != Some(false);
            g.online = Some(false);
            g.last_error = Some(why.to_string());
            changed
        };
        if changed {
            warn!(guardian = i, "guardian marked offline: {why}");
            self.publish();
        }
    }

    fn mark_up(&self, i: Idx, rtt: Duration, pending: usize, ledger: Option<WireLedger>) {
        let came_back = {
            let mut m = self.inner.lock().unwrap();
            let Some(g) = m.get_mut(&i) else { return };
            let came_back = g.online == Some(false);
            g.online = Some(true);
            g.last_seen_ms = Some(unix_ms());
            g.rtt_ms = Some(rtt.as_millis() as u64);
            g.pending = pending;
            g.ledger = ledger;
            g.last_error = None;
            came_back
        };
        if came_back {
            info!(guardian = i, "guardian back online");
        }
        self.publish();
    }

    pub fn snapshot(&self) -> Vec<GuardianStatus> {
        self.inner.lock().unwrap().values().cloned().collect()
    }

    fn publish(&self) {
        self.events.emit(json!({ "type": "guardians", "guardians": self.snapshot() }));
    }
}

/// Ping every guardian every `interval`; a guardian that misses a ping is marked down,
/// one that answers is marked up with its ledger totals.
pub fn spawn_heartbeats(guardians: Vec<Arc<dyn GuardianLink>>, status: Arc<Status>, interval: Duration, next_req: Arc<std::sync::atomic::AtomicU64>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            // One request id per round, so the pings travel as a single group message.
            let req = next_req.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            for g in &guardians {
                let (g, status) = (g.clone(), status.clone());
                tokio::spawn(async move {
                    let started = Instant::now();
                    match tokio::time::timeout(interval, g.ping(req)).await {
                        Ok(Ok(p)) => status.mark_up(g.index(), started.elapsed(), p.pending, p.ledger),
                        // Our own publish failed: says nothing about the guardian.
                        Ok(Err(crate::link::LinkError::Transport(e))) => warn!(guardian = g.index(), "heartbeat not sent: {e}"),
                        Ok(Err(e)) => status.mark_down(g.index(), &e.to_string()),
                        Err(_) => status.mark_down(g.index(), "no heartbeat"),
                    }
                });
            }
        }
    });
}
