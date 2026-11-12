//! How the coordinator reaches a guardian. Milestone 2: in-process ([`LocalGuardian`]).
//! Milestone 3 adds a Marmot implementation of the same trait.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use rand_core::OsRng;
use splitnut_core::guardian::{Guardian, RequestId, SignItem, VerifyItem};
use splitnut_core::sign::Round1;
use splitnut_core::verify::Partial;
use splitnut_core::{conv, Idx, Scalar};
use splitnut_proto::WireOp;
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("guardian {0} is offline")]
    Offline(Idx),
    #[error("guardian {0} refused: {1}")]
    Refused(Idx, String),
    /// The coordinator could not get the request out (relay rejected it, rate limit, ...).
    /// Not the guardian's fault, so it is not marked offline for it.
    #[error("could not reach the relays: {0}")]
    Transport(String),
}

/// A guardian's heartbeat answer.
#[derive(Clone, Debug, Default)]
pub struct PingInfo {
    pub pending: usize,
    pub ledger: Option<splitnut_proto::WireLedger>,
}

/// Tells every guardian about finished signatures (one broadcast, no replies).
#[async_trait]
pub trait Announce: Send + Sync {
    /// `context` carries the operation (with input evidence) so every guardian records spends.
    async fn issued(&self, req: RequestId, outputs: Vec<splitnut_proto::WireIssued>, context: Option<WireOp>);
}

#[async_trait]
pub trait GuardianLink: Send + Sync {
    fn index(&self) -> Idx;
    /// Round 1; `context` is what the outputs are for (guardians check it before answering).
    async fn round1(&self, req: RequestId, items: Vec<SignItem>, context: Option<WireOp>) -> Result<Vec<Round1>, LinkError>;
    async fn round2(&self, req: RequestId, items: Vec<SignItem>, es: Vec<Scalar>) -> Result<Vec<Scalar>, LinkError>;
    async fn abort(&self, req: RequestId);
    async fn ping(&self, req: RequestId) -> Result<PingInfo, LinkError>;
    /// Partial evaluations for proofs given as `(amount, secret)`; the guardian computes
    /// `Y = hash_to_curve(secret)` itself. `context` is the operation they are inputs to.
    async fn verify(&self, req: RequestId, items: Vec<(u64, String)>, context: Option<WireOp>) -> Result<Vec<Partial>, LinkError>;
}

/// A guardian living inside the coordinator process, for tests and milestone 2.
/// It can be switched offline and given an artificial delay. It holds shares only, no ledger,
/// so it ignores operation context (the rules live in the guardian daemon).
pub struct LocalGuardian {
    index: Idx,
    inner: Mutex<Guardian>,
    online: AtomicBool,
    delay: Duration,
}

impl LocalGuardian {
    pub fn new(guardian: Guardian, delay: Duration) -> Self {
        Self { index: guardian.index(), inner: Mutex::new(guardian), online: AtomicBool::new(true), delay }
    }

    pub fn set_online(&self, online: bool) {
        self.online.store(online, Ordering::SeqCst);
    }

    /// Requests holding nonces (tests, dashboard).
    #[allow(dead_code)]
    pub async fn pending(&self) -> usize {
        self.inner.lock().await.pending_requests()
    }

    async fn gate(&self) -> Result<(), LinkError> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        if self.online.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(LinkError::Offline(self.index))
        }
    }
}

#[async_trait]
impl GuardianLink for LocalGuardian {
    fn index(&self) -> Idx {
        self.index
    }

    async fn round1(&self, req: RequestId, items: Vec<SignItem>, _context: Option<WireOp>) -> Result<Vec<Round1>, LinkError> {
        self.gate().await?;
        let mut g = self.inner.lock().await;
        g.round1(req, &items, &mut OsRng).map_err(|e| LinkError::Refused(self.index, e.to_string()))
    }

    async fn round2(&self, req: RequestId, items: Vec<SignItem>, es: Vec<Scalar>) -> Result<Vec<Scalar>, LinkError> {
        self.gate().await?;
        let mut g = self.inner.lock().await;
        g.round2(req, &items, &es).map_err(|e| LinkError::Refused(self.index, e.to_string()))
    }

    async fn abort(&self, req: RequestId) {
        self.inner.lock().await.abort(req);
    }

    async fn ping(&self, _req: RequestId) -> Result<PingInfo, LinkError> {
        self.gate().await?;
        Ok(PingInfo { pending: self.inner.lock().await.pending_requests(), ledger: None })
    }

    async fn verify(&self, _req: RequestId, items: Vec<(u64, String)>, _context: Option<WireOp>) -> Result<Vec<Partial>, LinkError> {
        self.gate().await?;
        let refused = |e: splitnut_core::Error| LinkError::Refused(self.index, e.to_string());
        let items = items
            .iter()
            .map(|(amount, secret)| Ok(VerifyItem { amount: *amount, y: conv::hash_to_curve(secret.as_bytes())? }))
            .collect::<Result<Vec<_>, splitnut_core::Error>>()
            .map_err(refused)?;
        let g = self.inner.lock().await;
        g.verify(&items, &mut OsRng).map_err(refused)
    }
}
