//! The threshold signer: CDK's `Signatory` trait, backed by t-of-n guardians.
//!
//! `blind_sign`: two rounds (nonce commitments, then responses) with one fixed signer set,
//! every share checked against the guardian's public share before combining. Round 1 goes to
//! every guardian not known to be down and continues at the first t valid answers. If a signer
//! drops or misbehaves in round 2, the request restarts with fresh nonces without it. After
//! success the finished signatures are announced to all guardians for their ledgers.
//!
//! `verify_proofs`: one round of partial evaluations with per-guardian DLEQs.
//!
//! Refusals say why ("guardian 2: offline; guardian 3: hourly issuance cap …"). Errors crossing
//! CDK's gRPC boundary keep only a few kinds, so everything else is `Custom(detail)`.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cdk_common::error::Error;
use cdk_common::{Amount, BlindSignature, BlindedMessage, CurrencyUnit, Id, Keys, Proof, PublicKey};
use cdk_signatory::signatory::{RotateKeyArguments, Signatory, SignatoryKeySet, SignatoryKeysets};
use futures::stream::{FuturesUnordered, StreamExt};
use serde_json::json;
use splitnut_core::guardian::{RequestId, SignItem};
use splitnut_core::keyfile::{to_hex_point, to_hex_scalar, PublicKeyset};
use splitnut_core::sign::{self, Round1, Session};
use splitnut_core::verify::{self, Partial};
use splitnut_core::{conv, Idx, ProjectivePoint, Scalar};
use splitnut_proto::WireIssued;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::link::{Announce, GuardianLink, LinkError};
use crate::status::{unix_ms, Events, Status};

/// How many times a signing request restarts (fresh nonces) after a round-2 failure.
const MAX_SIGN_ATTEMPTS: usize = 3;

/// Per-amount public material, parsed once at startup.
struct AmountKeys {
    mint_key: ProjectivePoint,
    public_shares: BTreeMap<Idx, ProjectivePoint>,
}

pub struct ThresholdSigner {
    t: usize,
    keyset_id: Id,
    amounts: BTreeMap<u64, AmountKeys>,
    keysets: SignatoryKeysets,
    /// Kept alive so subscribers' streams stay open.
    keyset_updates: watch::Sender<SignatoryKeysets>,
    guardians: Vec<Arc<dyn GuardianLink>>,
    announce: Option<Arc<dyn Announce>>,
    status: Arc<Status>,
    events: Arc<Events>,
    next_req: Arc<AtomicU64>,
    timeout: Duration,
}

type Triple = (ProjectivePoint, Scalar, Scalar);
type Reasons = Vec<(Idx, String)>;

fn custom(msg: impl Into<String>) -> Error {
    Error::Custom(msg.into())
}

/// Request ids start at the current time in microseconds, so a restarted coordinator never
/// reuses an id a guardian may still hold nonces for.
pub fn request_counter() -> Arc<AtomicU64> {
    Arc::new(AtomicU64::new(unix_ms() * 1000))
}

impl ThresholdSigner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        keyset: &PublicKeyset,
        guardians: Vec<Arc<dyn GuardianLink>>,
        announce: Option<Arc<dyn Announce>>,
        status: Arc<Status>,
        events: Arc<Events>,
        next_req: Arc<AtomicU64>,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let keyset_id = Id::from_str(&keyset.keyset_id)?;
        let unit = CurrencyUnit::from_str(&keyset.unit)?;
        let mut amounts = BTreeMap::new();
        let mut keys = BTreeMap::new();
        for amount in keyset.amounts() {
            let mint_key = keyset.mint_key(amount)?;
            keys.insert(Amount::from(amount), conv::public_key(&mint_key)?);
            amounts.insert(amount, AmountKeys { mint_key, public_shares: keyset.public_shares_for(amount)? });
        }
        let keys = Keys::new(keys);
        // The keyset id must be the one CDK derives from these keys, or wallets reject it.
        anyhow::ensure!(
            Id::v2_from_data(&keys, &unit, keyset.input_fee_ppk, None) == keyset_id,
            "keyset id in public.json does not match its keys"
        );
        let keysets = SignatoryKeysets {
            pubkey: PublicKey::from_hex(&keyset.identity_pubkey)?,
            keysets: vec![SignatoryKeySet {
                id: keyset_id,
                unit,
                active: true,
                keys,
                amounts: keyset.amounts(),
                input_fee_ppk: keyset.input_fee_ppk,
                final_expiry: None,
                issuer_version: None,
                version: 1,
            }],
        };
        let (keyset_updates, _) = watch::channel(keysets.clone());
        Ok(Self {
            t: keyset.t as usize,
            keyset_id,
            amounts,
            keysets,
            keyset_updates,
            guardians,
            announce,
            status,
            events,
            next_req,
            timeout,
        })
    }

    fn next_req(&self) -> RequestId {
        self.next_req.fetch_add(1, Ordering::Relaxed)
    }

    fn keys_for(&self, keyset_id: &Id, amount: Amount) -> Result<&AmountKeys, Error> {
        if *keyset_id != self.keyset_id {
            return Err(Error::UnknownKeySet);
        }
        self.amounts.get(&u64::from(amount)).ok_or(Error::UnknownKeySet)
    }

    fn refusal(&self, agreed: usize, reasons: &Reasons) -> Error {
        let mut reasons = reasons.clone();
        reasons.sort_by_key(|(i, _)| *i);
        reasons.dedup_by_key(|(i, _)| *i);
        let why = reasons.iter().map(|(i, r)| format!("guardian {i}: {r}")).collect::<Vec<_>>().join("; ");
        warn!(agreed, needed = self.t, %why, "quorum unavailable: refusing");
        custom(format!(
            "SplitNut quorum unavailable: {agreed} of {} required guardians answered ({why})",
            self.t
        ))
    }

    fn guardian(&self, index: Idx) -> &Arc<dyn GuardianLink> {
        self.guardians.iter().find(|g| g.index() == index).expect("known guardian")
    }

    /// Guardians to ask: not excluded and not known to be down. Down ones go into `reasons`.
    fn candidates(&self, exclude: &[Idx], reasons: &mut Reasons) -> Vec<Idx> {
        let mut out = vec![];
        for g in &self.guardians {
            let i = g.index();
            if exclude.contains(&i) {
                continue;
            }
            if self.status.is_down(i) {
                reasons.push((i, "offline".into()));
                continue;
            }
            out.push(i);
        }
        out
    }

    fn note_failure(&self, req: RequestId, i: Idx, round: &str, r: &Result<LinkError, ()>, reasons: &mut Reasons) {
        match r {
            Ok(e) => {
                warn!(req, guardian = i, "{round}: {e}");
                let msg = match e {
                    LinkError::Refused(_, m) => m.clone(),
                    LinkError::Offline(_) => "offline".into(),
                    LinkError::Transport(m) => format!("request not delivered ({m})"),
                };
                reasons.push((i, msg));
            }
            Err(()) => {
                warn!(req, guardian = i, "{round}: timed out");
                self.status.mark_down(i, "request timed out");
                reasons.push((i, "timed out".into()));
            }
        }
    }

    /// One signing attempt with fresh nonces. `Ok(Err(bad))` means: restart without `bad`.
    async fn sign_attempt(
        &self,
        req: RequestId,
        items: &[SignItem],
        keys: &[&AmountKeys],
        exclude: &[Idx],
        reasons: &mut Reasons,
    ) -> Result<Result<(Vec<Idx>, Vec<Triple>), Vec<Idx>>, Error> {
        // Round 1: ask every guardian not excluded or known down; continue as soon as t have
        // answered, so a dead guardian costs nothing. Everyone not chosen drops its nonces.
        let candidates = self.candidates(exclude, reasons);
        if candidates.len() < self.t {
            return Err(self.refusal(0, reasons));
        }
        let mut futs: FuturesUnordered<_> = candidates
            .iter()
            .map(|i| {
                let g = self.guardian(*i).clone();
                let items = items.to_vec();
                async move { (g.index(), tokio::time::timeout(self.timeout, g.round1(req, items)).await) }
            })
            .collect();
        let mut answered: Vec<(Idx, Vec<Round1>)> = vec![];
        while let Some((i, r)) = futs.next().await {
            match r {
                Ok(Ok(v)) if v.len() == items.len() => {
                    answered.push((i, v));
                    if answered.len() == self.t {
                        break;
                    }
                }
                Ok(Ok(_)) => reasons.push((i, "wrong number of items".into())),
                Ok(Err(e)) => self.note_failure(req, i, "round 1", &Ok(e), reasons),
                Err(_) => self.note_failure(req, i, "round 1", &Err(()), reasons),
            }
        }
        drop(futs);
        answered.sort_by_key(|(i, _)| *i);
        let chosen: Vec<Idx> = answered.iter().map(|(i, _)| *i).collect();
        let enough = answered.len() >= self.t;
        for i in candidates.iter().filter(|i| !enough || !chosen.contains(i)) {
            self.guardian(*i).abort(req).await;
        }
        if !enough {
            return Err(self.refusal(answered.len(), reasons));
        }
        let set = chosen;

        let mut sessions = Vec::with_capacity(items.len());
        for (j, (it, k)) in items.iter().zip(keys).enumerate() {
            let parts = answered.iter().map(|(i, r)| (*i, r[j])).collect();
            sessions.push(Session::new(k.mint_key, it.b, parts).map_err(|e| custom(format!("round 1: {e}")))?);
        }
        let es: Vec<Scalar> = sessions.iter().map(Session::challenge).collect();

        // Round 2 with exactly the same set.
        let replies = futures::future::join_all(set.iter().map(|i| {
            let g = self.guardian(*i).clone();
            let (items, es) = (items.to_vec(), es.clone());
            async move { (g.index(), tokio::time::timeout(self.timeout, g.round2(req, items, es)).await) }
        }))
        .await;
        let mut s_by_guardian: BTreeMap<Idx, Vec<Scalar>> = BTreeMap::new();
        let mut failed = vec![];
        for (i, r) in replies {
            match r {
                Ok(Ok(v)) if v.len() == items.len() => {
                    s_by_guardian.insert(i, v);
                }
                Ok(Ok(_)) => {
                    reasons.push((i, "wrong number of items".into()));
                    failed.push(i);
                }
                Ok(Err(e)) => {
                    self.note_failure(req, i, "round 2", &Ok(e), reasons);
                    failed.push(i);
                }
                Err(_) => {
                    self.note_failure(req, i, "round 2", &Err(()), reasons);
                    failed.push(i);
                }
            }
        }
        if !failed.is_empty() {
            return Ok(Err(failed));
        }

        let mut out = Vec::with_capacity(items.len());
        for (j, (session, k)) in sessions.into_iter().zip(keys).enumerate() {
            let s_parts: Vec<_> = set.iter().map(|i| (*i, s_by_guardian[i][j])).collect();
            match session.finish(&k.public_shares, &s_parts) {
                Ok(triple) => out.push(triple),
                Err(splitnut_core::Error::BadShare(i)) => {
                    warn!(req, guardian = i, "round 2: invalid share");
                    reasons.push((i, "sent an invalid share".into()));
                    return Ok(Err(vec![i]));
                }
                Err(e) => return Err(custom(format!("round 2: {e}"))),
            }
        }
        Ok(Ok((set, out)))
    }

    async fn announce_issued(&self, req: RequestId, items: &[SignItem], triples: &[Triple]) {
        let Some(announce) = &self.announce else { return };
        let outputs: Option<Vec<WireIssued>> = items
            .iter()
            .zip(triples)
            .map(|(it, (c, e, s))| {
                Some(WireIssued {
                    amount: it.amount,
                    b: to_hex_point(&it.b).ok()?,
                    c: to_hex_point(c).ok()?,
                    e: to_hex_scalar(e),
                    s: to_hex_scalar(s),
                })
            })
            .collect();
        if let Some(outputs) = outputs {
            announce.issued(req, outputs).await;
        }
    }
}

#[async_trait::async_trait]
impl Signatory for ThresholdSigner {
    fn name(&self) -> String {
        "splitnut".to_string()
    }

    async fn blind_sign(&self, blinded_messages: Vec<BlindedMessage>) -> Result<Vec<BlindSignature>, Error> {
        let started = Instant::now();
        let req = self.next_req();
        let mut items = Vec::with_capacity(blinded_messages.len());
        let mut keys = Vec::with_capacity(blinded_messages.len());
        for m in &blinded_messages {
            keys.push(self.keys_for(&m.keyset_id, m.amount)?);
            let b = conv::point(&m.blinded_secret).map_err(|e| custom(e.to_string()))?;
            items.push(SignItem { amount: u64::from(m.amount), b });
        }
        let total: u64 = items.iter().map(|i| i.amount).sum();

        let mut exclude = vec![];
        let mut reasons: Reasons = vec![];
        let mut result = Err(custom("SplitNut: signing failed after retries"));
        for attempt in 1..=MAX_SIGN_ATTEMPTS {
            // Each attempt gets its own request id, so guardians never see a reused id.
            let attempt_req = if attempt == 1 { req } else { self.next_req() };
            match self.sign_attempt(attempt_req, &items, &keys, &exclude, &mut reasons).await {
                Ok(Ok((set, triples))) => {
                    let sigs = blinded_messages
                        .iter()
                        .zip(keys.iter())
                        .zip(triples.iter())
                        .map(|((m, k), triple)| {
                            sign::blind_signature(m.amount, m.keyset_id, &m.blinded_secret, &k.mint_key, *triple)
                                .map_err(|e| custom(format!("combined signature: {e}")))
                        })
                        .collect::<Result<Vec<_>, _>>();
                    if let Ok(sigs) = &sigs {
                        let ms = started.elapsed().as_millis() as u64;
                        info!(req, signers = ?set, outputs = items.len(), amount = total, attempt, ms, "blind_sign ok");
                        self.events.emit(json!({
                            "type": "request", "op": "blind_sign", "req": req, "ok": true, "signers": set,
                            "outputs": items.len(), "amount": total, "attempt": attempt, "ms": ms,
                        }));
                        self.announce_issued(attempt_req, &items, &triples).await;
                        return Ok(sigs.clone());
                    }
                    result = sigs;
                    break;
                }
                Ok(Err(bad)) => {
                    warn!(req, attempt, excluded = ?bad, "blind_sign: restarting with fresh nonces");
                    exclude.extend(bad);
                }
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        let err = match result {
            Err(e) => e,
            Ok(_) => unreachable!(),
        };
        self.events.emit(json!({
            "type": "request", "op": "blind_sign", "req": req, "ok": false, "outputs": items.len(),
            "amount": total, "ms": started.elapsed().as_millis() as u64, "error": err.to_string(),
        }));
        Err(err)
    }

    async fn verify_proofs(&self, proofs: Vec<Proof>) -> Result<(), Error> {
        let started = Instant::now();
        let req = self.next_req();
        let total: u64 = proofs.iter().map(|p| u64::from(p.amount)).sum();
        let r = self.verify_inner(req, &proofs).await;
        let ms = started.elapsed().as_millis() as u64;
        match &r {
            Ok(signers) => {
                info!(req, ?signers, proofs = proofs.len(), ms, "verify_proofs ok");
                self.events.emit(json!({
                    "type": "request", "op": "verify_proofs", "req": req, "ok": true, "signers": signers,
                    "outputs": proofs.len(), "amount": total, "ms": ms,
                }));
            }
            Err(e) => self.events.emit(json!({
                "type": "request", "op": "verify_proofs", "req": req, "ok": false, "outputs": proofs.len(),
                "amount": total, "ms": ms, "error": e.to_string(),
            })),
        }
        r.map(|_| ())
    }

    async fn keysets(&self) -> Result<SignatoryKeysets, Error> {
        Ok(self.keysets.clone())
    }

    async fn subscribe_keysets(&self) -> Result<watch::Receiver<SignatoryKeysets>, Error> {
        Ok(self.keyset_updates.subscribe())
    }

    async fn rotate_keyset(&self, args: RotateKeyArguments) -> Result<SignatoryKeySet, Error> {
        warn!(unit = %args.unit, amounts = args.amounts.len(), fee = args.input_fee_ppk,
            "refusing keyset rotation: the dealer's keyset is the only one; check cdk-mintd's unit config matches public.json");
        Err(custom("SplitNut does not rotate keysets: the keyset comes from the dealer"))
    }
}

impl ThresholdSigner {
    /// Threshold proof check; returns the signer set on success.
    async fn verify_inner(&self, req: RequestId, proofs: &[Proof]) -> Result<Vec<Idx>, Error> {
        let mut ys = Vec::with_capacity(proofs.len());
        let mut cs = Vec::with_capacity(proofs.len());
        let mut keys = Vec::with_capacity(proofs.len());
        for p in proofs {
            keys.push(self.keys_for(&p.keyset_id, p.amount)?);
            ys.push(conv::hash_to_curve(p.secret.as_bytes()).map_err(|e| custom(e.to_string()))?);
            cs.push(conv::point(&p.c).map_err(|_| Error::DHKE(cdk_common::dhke::Error::TokenNotVerified))?);
        }
        let wire_items: Vec<(u64, String)> = proofs.iter().map(|p| (u64::from(p.amount), p.secret.to_string())).collect();

        let mut reasons: Reasons = vec![];
        let candidates = self.candidates(&[], &mut reasons);
        if candidates.len() < self.t {
            return Err(self.refusal(0, &reasons));
        }
        let mut futs: FuturesUnordered<_> = candidates
            .iter()
            .map(|i| {
                let g = self.guardian(*i).clone();
                let items = wire_items.clone();
                async move { (g.index(), tokio::time::timeout(self.timeout, g.verify(req, items)).await) }
            })
            .collect();

        // Take responders as they arrive; check as soon as t honest ones are in. A guardian
        // with a bad partial is dropped and the next responder takes its place.
        let mut answered: Vec<(Idx, Vec<Partial>)> = vec![];
        let mut bad: Vec<Idx> = vec![];
        loop {
            while answered.iter().filter(|(i, _)| !bad.contains(i)).count() < self.t {
                match futs.next().await {
                    Some((i, Ok(Ok(v)))) if v.len() == proofs.len() => answered.push((i, v)),
                    Some((i, Ok(Ok(_)))) => reasons.push((i, "wrong number of items".into())),
                    Some((i, Ok(Err(e)))) => self.note_failure(req, i, "verify", &Ok(e), &mut reasons),
                    Some((i, Err(_))) => self.note_failure(req, i, "verify", &Err(()), &mut reasons),
                    None => break,
                }
            }
            let mut set: Vec<&(Idx, Vec<Partial>)> = answered.iter().filter(|(i, _)| !bad.contains(i)).take(self.t).collect();
            if set.len() < self.t {
                return Err(self.refusal(set.len(), &reasons));
            }
            set.sort_by_key(|(i, _)| *i);
            let mut flagged = None;
            for j in 0..proofs.len() {
                let parts: Vec<_> = set.iter().map(|(i, v)| (*i, v[j])).collect();
                match verify::combine_and_check(&cs[j], &ys[j], &keys[j].public_shares, &parts) {
                    Ok(()) => {}
                    Err(splitnut_core::Error::BadShare(i)) => {
                        flagged = Some(i);
                        break;
                    }
                    Err(splitnut_core::Error::InvalidProof) => {
                        info!(req, proof = j, "verify_proofs: invalid proof");
                        return Err(Error::DHKE(cdk_common::dhke::Error::TokenNotVerified));
                    }
                    Err(e) => return Err(custom(format!("verify: {e}"))),
                }
            }
            match flagged {
                Some(i) => {
                    warn!(req, guardian = i, "verify: invalid partial, excluding guardian");
                    reasons.push((i, "sent an invalid partial".into()));
                    bad.push(i);
                }
                None => return Ok(set.iter().map(|(i, _)| *i).collect()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::{LinkError, LocalGuardian};
    use cdk_common::dhke;
    use cdk_common::secret::Secret;
    use rand_core::OsRng;
    use splitnut_core::guardian::Guardian;
    use splitnut_core::keyfile::deal;

    /// Wraps a guardian and corrupts its round-2 responses.
    struct Cheater(LocalGuardian);

    #[async_trait::async_trait]
    impl GuardianLink for Cheater {
        fn index(&self) -> Idx {
            self.0.index()
        }
        async fn round1(&self, req: RequestId, items: Vec<SignItem>) -> Result<Vec<Round1>, crate::link::LinkError> {
            self.0.round1(req, items).await
        }
        async fn round2(&self, req: RequestId, items: Vec<SignItem>, es: Vec<Scalar>) -> Result<Vec<Scalar>, LinkError> {
            Ok(self.0.round2(req, items, es).await?.into_iter().map(|s| s + Scalar::ONE).collect())
        }
        async fn abort(&self, req: RequestId) {
            self.0.abort(req).await
        }
        async fn ping(&self, req: RequestId) -> Result<crate::link::PingInfo, LinkError> {
            self.0.ping(req).await
        }
        async fn verify(&self, req: RequestId, items: Vec<(u64, String)>) -> Result<Vec<Partial>, LinkError> {
            let mut v = self.0.verify(req, items).await?;
            for p in &mut v {
                p.y_i += ProjectivePoint::GENERATOR;
            }
            Ok(v)
        }
    }

    struct Setup {
        signer: ThresholdSigner,
        locals: Vec<Arc<LocalGuardian>>,
        keyset: PublicKeyset,
    }

    fn setup(t: u16, n: u16, cheater: Option<Idx>) -> Setup {
        let (keyset, files) = deal(t, n, &CurrencyUnit::Sat, 0, 32, &mut OsRng).unwrap();
        let mut locals = vec![];
        let mut links: Vec<Arc<dyn GuardianLink>> = vec![];
        for f in &files {
            let g = LocalGuardian::new(Guardian::from_file(f).unwrap(), Duration::ZERO);
            if Some(f.index) == cheater {
                links.push(Arc::new(Cheater(g)));
            } else {
                let g = Arc::new(g);
                locals.push(g.clone());
                links.push(g);
            }
        }
        let events = Events::new();
        let indices: Vec<Idx> = files.iter().map(|f| f.index).collect();
        let status = Status::new(&indices, events.clone());
        let signer = ThresholdSigner::new(&keyset, links, None, status, events, request_counter(), Duration::from_secs(2)).unwrap();
        Setup { signer, locals, keyset }
    }

    /// Wallet side: blind `amounts`, have the signer sign, check DLEQs, unblind into proofs.
    async fn mint(s: &Setup, amounts: &[u64]) -> Result<Vec<Proof>, Error> {
        let id = Id::from_str(&s.keyset.keyset_id).unwrap();
        let mut msgs = vec![];
        let mut secrets = vec![];
        for &a in amounts {
            let secret = Secret::generate();
            let (b, r) = dhke::blind_message(secret.as_bytes(), None).unwrap();
            msgs.push(BlindedMessage::new(Amount::from(a), id, b));
            secrets.push((secret, r));
        }
        let sigs = s.signer.blind_sign(msgs.clone()).await?;
        let mut proofs = vec![];
        for ((sig, msg), (secret, r)) in sigs.iter().zip(&msgs).zip(secrets) {
            let k = conv::public_key(&s.keyset.mint_key(u64::from(msg.amount)).unwrap()).unwrap();
            sig.verify_dleq(k, msg.blinded_secret).expect("DLEQ verifies against the mint key");
            let c = dhke::unblind_message(&sig.c, &r, &k).unwrap();
            proofs.push(Proof::new(msg.amount, id, secret, c));
        }
        Ok(proofs)
    }

    #[tokio::test]
    async fn mint_and_verify_2_of_3() {
        let s = setup(2, 3, None);
        let proofs = mint(&s, &[1, 8, 512, 1 << 31]).await.unwrap();
        s.signer.verify_proofs(proofs.clone()).await.unwrap();

        // a forged proof (wrong C) is rejected
        let mut forged = proofs[0].clone();
        forged.c = proofs[1].c;
        assert!(s.signer.verify_proofs(vec![forged]).await.is_err());
        // no nonces left behind
        for g in &s.locals {
            assert_eq!(g.pending().await, 0);
        }
    }

    #[tokio::test]
    async fn one_guardian_down_still_signs() {
        let s = setup(2, 3, None);
        s.locals[0].set_online(false);
        let proofs = mint(&s, &[2, 4]).await.unwrap();
        s.signer.verify_proofs(proofs).await.unwrap();
    }

    #[tokio::test]
    async fn two_guardians_down_refuses_cleanly() {
        let s = setup(2, 3, None);
        s.locals[0].set_online(false);
        s.locals[1].set_online(false);
        let err = mint(&s, &[2]).await.unwrap_err();
        assert!(err.to_string().contains("quorum unavailable: 1 of 2"), "{err}");
        assert!(err.to_string().contains("guardian 1: guardian 1 is offline") || err.to_string().contains("guardian 1: offline"), "{err}");
        for g in &s.locals {
            assert_eq!(g.pending().await, 0, "aborted nonces are dropped");
        }
    }

    #[tokio::test]
    async fn cheating_guardian_is_excluded() {
        // Guardian 1 corrupts its shares; signing restarts with 2 and 3.
        let s = setup(2, 3, Some(1));
        let proofs = mint(&s, &[16, 32]).await.unwrap();
        s.signer.verify_proofs(proofs).await.unwrap();
    }

    #[tokio::test]
    async fn cheater_plus_offline_is_below_quorum() {
        let s = setup(2, 3, Some(1));
        s.locals[0].set_online(false); // guardian 2
        assert!(mint(&s, &[1]).await.is_err());
    }

    #[tokio::test]
    async fn rotation_refused_and_unknown_keyset_rejected() {
        let s = setup(2, 3, None);
        let args = RotateKeyArguments {
            unit: CurrencyUnit::Sat,
            amounts: vec![1],
            input_fee_ppk: 0,
            keyset_id_type: cdk_common::nuts::nut02::KeySetVersion::Version01,
            final_expiry: None,
        };
        assert!(s.signer.rotate_keyset(args).await.is_err());
        let other = Id::from_bytes(&[0u8; 8]).unwrap();
        let b = dhke::blind_message(b"x", None).unwrap().0;
        let err = s.signer.blind_sign(vec![BlindedMessage::new(Amount::from(1), other, b)]).await.unwrap_err();
        assert!(matches!(err, Error::UnknownKeySet));
    }
}
