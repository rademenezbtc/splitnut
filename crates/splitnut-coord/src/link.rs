//! How the coordinator reaches a guardian. Milestone 2: in-process ([`LocalGuardian`]).
//! Milestone 3 adds a Marmot implementation of the same trait.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use rand_core::OsRng;
use splitnut_core::guardian::{Guardian, RequestId, SignItem, VerifyItem};
use splitnut_core::sign::Round1;
use splitnut_core::verify::Partial;
use splitnut_core::{Idx, Scalar};
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("guardian {0} is offline")]
    Offline(Idx),
    #[error("guardian {0} refused: {1}")]
    Refused(Idx, String),
}

#[async_trait]
pub trait GuardianLink: Send + Sync {
    fn index(&self) -> Idx;
    async fn round1(&self, req: RequestId, items: Vec<SignItem>) -> Result<Vec<Round1>, LinkError>;
    async fn round2(&self, req: RequestId, items: Vec<SignItem>, es: Vec<Scalar>) -> Result<Vec<Scalar>, LinkError>;
    async fn abort(&self, req: RequestId);
    async fn verify(&self, items: Vec<VerifyItem>) -> Result<Vec<Partial>, LinkError>;
}

/// A guardian living inside the coordinator process, for tests and milestone 2.
/// It can be switched offline and given an artificial delay.
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

    async fn round1(&self, req: RequestId, items: Vec<SignItem>) -> Result<Vec<Round1>, LinkError> {
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

    async fn verify(&self, items: Vec<VerifyItem>) -> Result<Vec<Partial>, LinkError> {
        self.gate().await?;
        let g = self.inner.lock().await;
        g.verify(&items, &mut OsRng).map_err(|e| LinkError::Refused(self.index, e.to_string()))
    }
}
