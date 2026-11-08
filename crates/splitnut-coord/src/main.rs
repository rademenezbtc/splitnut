//! splitnut-coord: the remote signer that cdk-mintd talks to.
//!
//! Implements CDK's `Signatory` trait ([`signer::ThresholdSigner`]) and serves it with CDK's
//! own generic `start_grpc_server`, so the gRPC schema, mTLS and version check are exactly
//! what cdk-mintd expects. Holds no key material: each `blind_sign` / `verify_proofs` call
//! goes to t-of-n guardians and every share is checked before combining.
//!
//! Guardians are reached over Marmot (`--roster`, `--relay`), or run in-process for tests
//! (`--local-guardian`).

mod link;
mod marmot_link;
mod signer;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use splitnut_core::guardian::Guardian;
use splitnut_core::keyfile::{read_json, GuardianShareFile, PublicKeyset};
use splitnut_core::Idx;
use tracing::info;

use crate::link::{GuardianLink, LocalGuardian};
use crate::marmot_link::{Hub, MarmotLink};
use splitnut_marmot::{load_or_create_keys, MarmotNode, NodeConfig, NostrPublicKey, NostrToBech32, Role, Storage};
use crate::signer::ThresholdSigner;

#[derive(Parser)]
#[command(about = "SplitNut coordinator: threshold remote signer for cdk-mintd")]
struct Args {
    /// Print this coordinator's npub (creating the key file if needed) and exit
    #[arg(long)]
    keygen: bool,
    /// Coordinator Nostr secret key file (created if missing)
    #[arg(long, default_value = "coord.nsec")]
    keys: PathBuf,
    /// Roster: guardian index -> npub (JSON); enables Marmot mode
    #[arg(long)]
    roster: Option<PathBuf>,
    /// Relay URL for the Marmot group (repeat for several)
    #[arg(long = "relay")]
    relays: Vec<String>,
    /// Encrypted MLS database (default: next to the keys file)
    #[arg(long)]
    db: Option<PathBuf>,
    /// Public keyset written by splitnut-dealer
    #[arg(long, default_value = "shares/public.json")]
    public: PathBuf,
    /// Guardian share file to run in-process (repeat per guardian)
    #[arg(long = "local-guardian")]
    local_guardians: Vec<PathBuf>,
    /// Start these in-process guardians switched off (for testing quorum loss)
    #[arg(long = "offline")]
    offline: Vec<Idx>,
    /// gRPC listen address
    #[arg(long, default_value = "127.0.0.1:15060")]
    listen: SocketAddr,
    /// Directory with server.pem, server.key and ca.pem (mTLS); omit only for local tests
    #[arg(long)]
    tls_dir: Option<PathBuf>,
    /// Per-round guardian timeout in milliseconds
    #[arg(long, default_value_t = 5000)]
    timeout_ms: u64,
}

#[derive(serde::Deserialize)]
struct Roster {
    guardians: Vec<RosterEntry>,
}

#[derive(serde::Deserialize)]
struct RosterEntry {
    index: Idx,
    npub: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    if args.keygen {
        println!("{}", load_or_create_keys(&args.keys)?.public_key().to_bech32()?);
        return Ok(());
    }

    let keyset: PublicKeyset = read_json(&args.public).with_context(|| format!("reading {}", args.public.display()))?;
    let mut guardians: Vec<Arc<dyn GuardianLink>> = vec![];
    for path in &args.local_guardians {
        let file: GuardianShareFile = read_json(path).with_context(|| format!("reading {}", path.display()))?;
        anyhow::ensure!(file.keyset == keyset, "{} belongs to a different keyset", path.display());
        let local = LocalGuardian::new(Guardian::from_file(&file)?, Duration::ZERO);
        if args.offline.contains(&file.index) {
            local.set_online(false);
        }
        guardians.push(Arc::new(local));
    }
    if let Some(roster_path) = &args.roster {
        anyhow::ensure!(guardians.is_empty(), "use either --roster or --local-guardian, not both");
        anyhow::ensure!(!args.relays.is_empty(), "--roster needs at least one --relay");
        let roster: Roster = read_json(roster_path).with_context(|| format!("reading {}", roster_path.display()))?;
        let mut by_key = HashMap::new();
        for g in &roster.guardians {
            let pk = NostrPublicKey::parse(&g.npub).with_context(|| format!("guardian {} npub", g.index))?;
            anyhow::ensure!(keyset.public_shares.contains_key(&g.index), "guardian {} is not in the keyset", g.index);
            anyhow::ensure!(by_key.insert(pk, g.index).is_none(), "duplicate npub in roster");
        }
        anyhow::ensure!(by_key.len() == keyset.n as usize, "roster has {} guardians, keyset has n={}", by_key.len(), keyset.n);
        let keys = load_or_create_keys(&args.keys)?;
        let node = MarmotNode::start(NodeConfig {
            keys: keys.clone(),
            relays: args.relays.clone(),
            storage: Storage::File(args.db.clone().unwrap_or_else(|| args.keys.with_extension("mls.sqlite"))),
            role: Role::Coordinator { guardians: roster.guardians.iter().map(|g| NostrPublicKey::parse(&g.npub)).collect::<Result<_, _>>()? },
        })
        .await?;
        info!(npub = %keys.public_key().to_bech32()?, relays = ?args.relays, "coordinator Marmot node started");
        let hub = Hub::start(node.clone(), keyset.keyset_id.clone(), by_key);
        let mut indices: Vec<Idx> = roster.guardians.iter().map(|g| g.index).collect();
        indices.sort_unstable();
        for i in indices {
            guardians.push(Arc::new(MarmotLink::new(i, hub.clone())));
        }
        tokio::spawn(async move {
            if node.wait_ready(Duration::from_secs(600)).await {
                info!("guardian group ready");
            } else {
                tracing::warn!("guardian group still not ready after 10 minutes");
            }
        });
    }
    anyhow::ensure!(!guardians.is_empty(), "no guardians configured: use --roster or --local-guardian");

    let signer = ThresholdSigner::new(&keyset, guardians, Duration::from_millis(args.timeout_ms))?;
    info!(
        keyset = %keyset.keyset_id, t = keyset.t, n = keyset.n, offline = ?args.offline,
        "SplitNut coordinator ready (holds no key material)"
    );
    cdk_signatory::start_grpc_server(Arc::new(signer), args.listen, args.tls_dir).await?;
    Ok(())
}
