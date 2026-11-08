//! splitnut-guardian: one of n guardians, each holding one share of every mint key.
//!
//! Joins the coordinator's Marmot group, then answers signing and proof-check requests with
//! partial results. Accepts requests only from the pinned coordinator key, only when
//! addressed to its own index, and only when fresh (stale replays from relay history are
//! ignored). Its MLS state is kept in an encrypted SQLite file, so a restart resumes the group.
//!
//! Usage:
//!   splitnut-guardian keygen --keys g1.nsec              # prints the npub for the roster
//!   splitnut-guardian run --share guardian-1.json --keys g1.nsec \
//!       --coordinator npub1... --relay ws://127.0.0.1:7777

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rand_core::OsRng;
use splitnut_core::guardian::{Guardian, VerifyItem};
use splitnut_core::keyfile::{read_json, GuardianShareFile};
use splitnut_core::conv;
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
        Cmd::Run { share, keys, coordinator, relays, db, max_age_secs } => {
            run(share, keys, coordinator, relays, db, max_age_secs).await
        }
    }
}

async fn run(
    share: PathBuf,
    keys_path: PathBuf,
    coordinator: String,
    relays: Vec<String>,
    db: Option<PathBuf>,
    max_age_secs: u64,
) -> Result<()> {
    let file: GuardianShareFile = read_json(&share).with_context(|| format!("reading {}", share.display()))?;
    let mut guardian = Guardian::from_file(&file).context("share file failed its self-check")?;
    let index = guardian.index();
    let keyset_id = guardian.keyset_id().to_string();
    let keys = load_or_create_keys(&keys_path)?;
    let coordinator = NostrPublicKey::parse(&coordinator).context("coordinator npub")?;
    let db = db.unwrap_or_else(|| keys_path.with_extension("mls.sqlite"));

    let node = MarmotNode::start(NodeConfig {
        keys: keys.clone(),
        relays,
        storage: Storage::File(db),
        role: Role::Guardian { coordinator },
    })
    .await?;
    info!(index, npub = %keys.public_key().to_bech32()?, keyset = %keyset_id, "guardian started");
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
            Ok(Wire::Request(r)) if r.to == index => r,
            Ok(_) => continue,
            Err(e) => {
                warn!("malformed request: {e}");
                continue;
            }
        };
        let age = splitnut_marmot::NostrTimestamp::now().as_secs().saturating_sub(msg.created_at.as_secs());
        if age > max_age_secs {
            debug!(req = req.req, age, "ignoring stale request");
            continue;
        }
        let body = handle(&mut guardian, &keyset_id, &req.body, req.req);
        let Some(body) = body else { continue };
        if let ResponseBody::Error { msg } = &body {
            warn!(req = req.req, kind = req.body.kind(), "refusing: {msg}");
        } else {
            info!(req = req.req, kind = req.body.kind(), "answered");
        }
        let resp = Wire::Response(Response { v: VERSION, from: index, req: req.req, body });
        if let Err(e) = node.send(resp.to_json()).await {
            warn!(req = req.req, "sending response: {e}");
        }
    }
    Ok(())
}

/// Answer one request. `None` means no reply is due (abort).
fn handle(g: &mut Guardian, keyset_id: &str, body: &RequestBody, req: u64) -> Option<ResponseBody> {
    let err = |m: String| Some(ResponseBody::Error { msg: m });
    let check_keyset = |k: &str| if k == keyset_id { Ok(()) } else { Err(format!("unknown keyset {k}")) };
    match body {
        RequestBody::Ping => Some(ResponseBody::Pong { pending: g.pending_requests() }),
        RequestBody::Abort => {
            g.abort(req);
            None
        }
        RequestBody::Sign1 { keyset, items } => {
            if let Err(m) = check_keyset(keyset) {
                return err(m);
            }
            let r = sign_items_from_wire(items)
                .and_then(|items| g.round1(req, &items, &mut OsRng))
                .and_then(|parts| parts.iter().map(round1_to_wire).collect::<Result<Vec<_>, _>>());
            match r {
                Ok(parts) => Some(ResponseBody::Sign1 { parts }),
                Err(e) => err(e.to_string()),
            }
        }
        RequestBody::Sign2 { keyset, items, es } => {
            if let Err(m) = check_keyset(keyset) {
                return err(m);
            }
            let r = sign_items_from_wire(items)
                .and_then(|items| Ok((items, scalars_from_wire(es)?)))
                .and_then(|(items, es)| g.round2(req, &items, &es));
            match r {
                Ok(s) => Some(ResponseBody::Sign2 { s: scalars_to_wire(&s) }),
                Err(e) => err(e.to_string()),
            }
        }
        RequestBody::Verify { keyset, items } => {
            if let Err(m) = check_keyset(keyset) {
                return err(m);
            }
            let r = items
                .iter()
                .map(|it| Ok(VerifyItem { amount: it.amount, y: conv::hash_to_curve(it.secret.as_bytes())? }))
                .collect::<Result<Vec<_>, splitnut_core::Error>>()
                .and_then(|items| g.verify(&items, &mut OsRng))
                .and_then(|ps| ps.iter().map(partial_to_wire).collect::<Result<Vec<_>, _>>());
            match r {
                Ok(partials) => Some(ResponseBody::Verify { partials }),
                Err(e) => err(e.to_string()),
            }
        }
    }
}
