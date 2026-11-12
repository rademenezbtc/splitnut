//! splitnut-guardian: one of n guardians, each holding one share of every mint key.
//!
//! Joins the coordinator's Marmot group, then answers signing and proof-check requests with
//! partial results, for operations that pass its rules (see `policy`). Accepts requests only from the pinned coordinator key, only when
//! addressed to its own index, and only when fresh (stale replays from relay history are
//! ignored). Its MLS state is kept in an encrypted SQLite file, so a restart resumes the group.
//!
//! Usage:
//!   splitnut-guardian keygen --keys g1.nsec              # prints the npub for the roster
//!   splitnut-guardian run --share guardian-1.json --keys g1.nsec \
//!       --coordinator npub1... --relay ws://127.0.0.1:7777

mod ledger;
mod policy;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rand_core::OsRng;
use std::str::FromStr;

use cashu::nuts::nut02::Id;
use cashu::Amount;
use ledger::Ledger;
use policy::Rules;
use splitnut_core::guardian::{Guardian, VerifyItem};
use splitnut_core::keyfile::{point_hex, read_json, scalar_hex, to_hex_point, GuardianShareFile, PublicKeyset};
use splitnut_core::{conv, sign};
use splitnut_marmot::{load_or_create_keys, MarmotNode, NodeConfig, NostrPublicKey, NostrToBech32, Role, Storage};
use splitnut_proto::*;
use tracing::{debug, info, warn};

#[derive(Parser)]
#[command(about = "SplitNut guardian: holds one share of every mint key")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create (or read) this guardian's Nostr key and print its npub
    Keygen {
        #[arg(long)]
        keys: PathBuf,
    },
    /// Join the group and serve signing requests
    Run {
        /// Share file from splitnut-dealer
        #[arg(long)]
        share: PathBuf,
        /// Nostr secret key file (created if missing)
        #[arg(long)]
        keys: PathBuf,
        /// The coordinator's npub (the only key this guardian takes requests from)
        #[arg(long)]
        coordinator: String,
        /// Relay URL (repeat for several)
        #[arg(long = "relay", required = true)]
        relays: Vec<String>,
        /// Encrypted MLS database (default: next to the keys file)
        #[arg(long)]
        db: Option<PathBuf>,
        /// Ignore requests older than this many seconds
        #[arg(long, default_value_t = 30)]
        max_age_secs: u64,
        /// Most sat this guardian will help issue per rolling hour (0 = no cap)
        #[arg(long, default_value_t = 100_000)]
        cap_per_hour: u64,
        /// Ledger database (default: next to the keys file)
        #[arg(long)]
        ledger: Option<PathBuf>,
        /// Sign requests that come without operation context (a stock cdk-mintd), capped but
        /// unchecked, as in v1. Off by default: such requests are refused.
        #[arg(long)]
        allow_contextless: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    match Args::parse().cmd {
        Cmd::Keygen { keys } => {
            let k = load_or_create_keys(&keys)?;
            println!("{}", k.public_key().to_bech32()?);
            Ok(())
        }
        Cmd::Run { share, keys, coordinator, relays, db, max_age_secs, cap_per_hour, ledger, allow_contextless } => {
            run(share, keys, coordinator, relays, db, max_age_secs, cap_per_hour, ledger, allow_contextless).await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    share: PathBuf,
    keys_path: PathBuf,
    coordinator: String,
    relays: Vec<String>,
    db: Option<PathBuf>,
    max_age_secs: u64,
    cap_per_hour: u64,
    ledger_path: Option<PathBuf>,
    allow_contextless: bool,
) -> Result<()> {
    let file: GuardianShareFile = read_json(&share).with_context(|| format!("reading {}", share.display()))?;
    let guardian = Guardian::from_file(&file).context("share file failed its self-check")?;
    let index = guardian.index();
    let keys = load_or_create_keys(&keys_path)?;
    let coordinator = NostrPublicKey::parse(&coordinator).context("coordinator npub")?;
    let db = db.unwrap_or_else(|| keys_path.with_extension("mls.sqlite"));
    let ledger_path = ledger_path.unwrap_or_else(|| keys_path.with_extension("ledger.sqlite"));
    let ledger = Ledger::open(&ledger_path, cap_per_hour).context("opening ledger")?;
    let rules = Rules::new(file.keyset.clone(), allow_contextless);
    let mut state = State { keyset_id: Id::from_str(&file.keyset.keyset_id)?, keyset: file.keyset.clone(), guardian, ledger, rules };

    let node = MarmotNode::start(NodeConfig {
        keys: keys.clone(),
        relays,
        storage: Storage::File(db),
        role: Role::Guardian { coordinator },
    })
    .await?;
    let t = state.ledger.totals(now());
    info!(
        index, npub = %keys.public_key().to_bech32()?, keyset = %state.keyset.keyset_id, cap_per_hour, allow_contextless,
        issued = t.issued, redeemed = t.redeemed, "guardian started"
    );
    let mut rx = node.subscribe();
    if !node.is_ready() {
        info!("waiting to be welcomed into the group");
    }

    loop {
        let msg = match rx.recv().await {
            Ok(m) => m,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                warn!("dropped {n} messages");
                continue;
            }
            Err(_) => break,
        };
        if msg.from != coordinator {
            debug!(from = %msg.from, "ignoring message not from the coordinator");
            continue;
        }
        let req = match Wire::from_json(&msg.content) {
            Ok(Wire::Request(r)) if r.is_for(index) => r,
            Ok(_) => continue,
            Err(e) => {
                warn!("malformed request: {e}");
                continue;
            }
        };
        let age = now().saturating_sub(msg.created_at.as_secs());
        if age > max_age_secs {
            debug!(req = req.req, age, "ignoring stale request");
            continue;
        }
        let Some(body) = state.handle(&req.body, req.req) else { continue };
        match &body {
            ResponseBody::Error { msg } => warn!(req = req.req, kind = req.body.kind(), "refusing: {msg}"),
            ResponseBody::Pong { .. } => debug!(req = req.req, "pong"),
            _ => info!(req = req.req, kind = req.body.kind(), "answered"),
        }
        let resp = Wire::Response(Response { v: VERSION, from: index, req: req.req, body });
        if let Err(e) = node.send(resp.to_json()).await {
            warn!(req = req.req, "sending response: {e}");
        }
    }
    Ok(())
}

fn now() -> u64 {
    splitnut_marmot::NostrTimestamp::now().as_secs()
}

struct State {
    guardian: Guardian,
    ledger: Ledger,
    rules: Rules,
    keyset: PublicKeyset,
    keyset_id: Id,
}

impl State {
    /// Answer one request. `None` means no reply is due (abort, issued).
    fn handle(&mut self, body: &RequestBody, req: u64) -> Option<ResponseBody> {
        let err = |m: String| Some(ResponseBody::Error { msg: m });
        if let Some(k) = body_keyset(body) {
            if k != self.keyset.keyset_id {
                return err(format!("unknown keyset {k}"));
            }
        }
        match body {
            RequestBody::Ping => {
                let t = self.ledger.totals(now());
                Some(ResponseBody::Pong {
                    pending: self.guardian.pending_requests(),
                    ledger: Some(WireLedger {
                        issued: t.issued,
                        redeemed: t.redeemed,
                        outstanding: t.outstanding,
                        signed_last_hour: t.signed_last_hour,
                        cap_per_hour: t.cap_per_hour,
                        duplicates: t.duplicates,
                    }),
                })
            }
            RequestBody::Abort => {
                self.guardian.abort(req);
                None
            }
            RequestBody::Sign1 { items, context, .. } => {
                // Round 1 already reveals this guardian's share of each signature, so the
                // operation is checked (and recorded) here, before anything is released.
                if let Err(m) = self.rules.approve_sign(&self.ledger, items, context.as_ref(), now()) {
                    return err(m);
                }
                if let Some(c) = context {
                    info!(req, operation = c.kind(), outputs = items.len(), "operation approved");
                }
                let r = sign_items_from_wire(items)
                    .and_then(|items| self.guardian.round1(req, &items, &mut OsRng))
                    .and_then(|parts| parts.iter().map(round1_to_wire).collect::<Result<Vec<_>, _>>());
                match r {
                    Ok(parts) => Some(ResponseBody::Sign1 { parts }),
                    Err(e) => err(e.to_string()),
                }
            }
            RequestBody::Sign2 { items, es, .. } => {
                // Approved and recorded in round 1; round 2 only completes the DLEQ.
                let r = sign_items_from_wire(items)
                    .and_then(|items| Ok((items, scalars_from_wire(es)?)))
                    .and_then(|(items, es)| self.guardian.round2(req, &items, &es));
                match r {
                    Ok(s) => Some(ResponseBody::Sign2 { s: scalars_to_wire(&s) }),
                    Err(e) => err(e.to_string()),
                }
            }
            RequestBody::Verify { items, context, .. } => {
                let ys = items
                    .iter()
                    .map(|it| Ok(VerifyItem { amount: it.amount, y: conv::hash_to_curve(it.secret.as_bytes())? }))
                    .collect::<Result<Vec<_>, splitnut_core::Error>>();
                let ys = match ys {
                    Ok(ys) => ys,
                    Err(e) => return err(e.to_string()),
                };
                let seen: Vec<(String, u64)> = ys.iter().filter_map(|v| Some((to_hex_point(&v.y).ok()?, v.amount))).collect();
                if let Err(m) = self.rules.approve_verify(&self.ledger, &seen, context.as_ref(), now()) {
                    return err(m);
                }
                match self.guardian.verify(&ys, &mut OsRng) {
                    Ok(partials) => {
                        match partials.iter().map(partial_to_wire).collect::<Result<Vec<_>, _>>() {
                            Ok(partials) => Some(ResponseBody::Verify { partials }),
                            Err(e) => err(e.to_string()),
                        }
                    }
                    Err(e) => err(e.to_string()),
                }
            }
            RequestBody::Issued { outputs, context, .. } => {
                let mut ok = vec![];
                let mut bad = 0;
                for o in outputs {
                    let parsed = (|| -> Result<_, splitnut_core::Error> {
                        Ok((point_hex(&o.b)?, (point_hex(&o.c)?, scalar_hex(&o.e)?, scalar_hex(&o.s)?), self.keyset.mint_key(o.amount)?))
                    })();
                    match parsed {
                        Ok((b, triple, k)) if sign::verify_issued(Amount::from(o.amount), self.keyset_id, &b, &k, triple) => {
                            ok.push((o.b.clone(), o.amount))
                        }
                        _ => bad += 1,
                    }
                }
                if bad > 0 {
                    warn!(req, bad, "announced signatures that do not verify; not counted");
                }
                match self.ledger.record_issued(&ok, now()) {
                    Ok(added) if !ok.is_empty() => info!(req, added, outputs = ok.len(), "issuance verified and recorded"),
                    Ok(_) => {}
                    Err(e) => warn!("ledger: {e}"),
                }
                if let (Some(c), 0) = (context, bad) {
                    let announced: Vec<(u64, String)> = outputs.iter().map(|o| (o.amount, o.b.clone())).collect();
                    match self.rules.apply_announcement(&self.ledger, &announced, c, now()) {
                        Ok(Some(conflict)) => warn!(req, "DOUBLE SPEND: {conflict}"),
                        Ok(None) => debug!(req, operation = c.kind(), "announcement applied"),
                        Err(e) => warn!(req, operation = c.kind(), "announcement not applied: {e}"),
                    }
                }
                None
            }
        }
    }
}

fn body_keyset(body: &RequestBody) -> Option<&str> {
    match body {
        RequestBody::Sign1 { keyset, .. }
        | RequestBody::Sign2 { keyset, .. }
        | RequestBody::Verify { keyset, .. }
        | RequestBody::Issued { keyset, .. } => Some(keyset),
        RequestBody::Abort | RequestBody::Ping => None,
    }
}
