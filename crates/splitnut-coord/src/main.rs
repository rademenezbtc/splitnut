//! splitnut-coord: the remote signer that cdk-mintd talks to.
//!
//! Implements CDK's `Signatory` trait ([`signer::ThresholdSigner`]) and serves it with CDK's
//! own generic `start_grpc_server`, so the gRPC schema, mTLS and version check are exactly
//! what cdk-mintd expects. Holds no key material: each `blind_sign` / `verify_proofs` call
//! goes to t-of-n guardians and every share is checked before combining.
//!
//! Guardians are reached over Marmot (`--roster`, `--relay`), or run in-process for tests
//! (`--local-guardian`).
//!
//! `--dkg` runs distributed key generation with the guardians instead (they run
//! `splitnut-guardian dkg`), writes the public keyset to `--public` and exits.

mod dashboard;
mod dkg;
mod link;
mod marmot_link;
mod signer;
mod status;

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
use crate::link::Announce;
use crate::signer::{request_counter, ThresholdSigner};
use crate::status::{spawn_heartbeats, Events, Status};

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
    /// Seconds between guardian heartbeats (a guardian missing one is treated as offline)
    #[arg(long, default_value_t = 3)]
    heartbeat_secs: u64,
    /// Serve the dashboard here, e.g. 127.0.0.1:8090
    #[arg(long)]
    dashboard: Option<SocketAddr>,
    /// Relay wire-tap stats URL for the dashboard (splitnut-relay --http-port)
    #[arg(long)]
    relay_tap_url: Option<String>,
    /// Run distributed key generation with the roster's guardians, write the public keyset to
    /// `--public`, and exit
    #[arg(long)]
    dkg: bool,
    /// Key generation: threshold
    #[arg(short, long, default_value_t = 2)]
    t: u16,
    /// Key generation: unit (must match cdk-mintd's)
    #[arg(long, default_value = "sat")]
    unit: String,
    /// Key generation: input fee in ppk (must match cdk-mintd's)
    #[arg(long, default_value_t = 0)]
    input_fee_ppk: u64,
    /// Key generation: amounts 2^0 .. 2^(max_order-1); cdk-mintd's default is 32
    #[arg(long, default_value_t = 32)]
    max_order: u32,
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

    if args.dkg {
        return run_dkg(&args).await;
    }

    let keyset: PublicKeyset = read_json(&args.public).with_context(|| format!("reading {}", args.public.display()))?;
    let mut guardians: Vec<Arc<dyn GuardianLink>> = vec![];
    let mut announce: Option<Arc<dyn Announce>> = None;
    let mut marmot: Option<MarmotNode> = None;
    let mut coord_npub = None;
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
        coord_npub = Some(keys.public_key().to_bech32()?);
        let hub = Hub::start(node.clone(), keyset.keyset_id.clone(), by_key);
        announce = Some(hub.clone());
        marmot = Some(node.clone());
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

    let events = Events::new();
    let indices: Vec<Idx> = guardians.iter().map(|g| g.index()).collect();
    let status = Status::new(&indices, events.clone());
    let next_req = request_counter();
    spawn_heartbeats(guardians.clone(), status.clone(), Duration::from_secs(args.heartbeat_secs.max(1)), next_req.clone());
    let signer = ThresholdSigner::new(
        &keyset,
        guardians,
        announce,
        status.clone(),
        events.clone(),
        next_req,
        Duration::from_millis(args.timeout_ms),
    )?;
    if let Some(addr) = args.dashboard {
        let dash = Arc::new(dashboard::Dash {
            events,
            status,
            marmot,
            config: serde_json::json!({
                "t": keyset.t, "n": keyset.n, "keyset": keyset.keyset_id, "unit": keyset.unit,
                "coordinator": coord_npub, "relays": args.relays, "relay_tap_url": args.relay_tap_url,
                "mode": if args.roster.is_some() { "marmot" } else { "local" },
            }),
        });
        tokio::spawn(async move {
            if let Err(e) = dashboard::serve(addr, dash).await {
                tracing::error!("dashboard: {e}");
            }
        });
    }
    info!(
        keyset = %keyset.keyset_id, t = keyset.t, n = keyset.n, offline = ?args.offline,
        "SplitNut coordinator ready (holds no key material)"
    );
    cdk_signatory::start_grpc_server(Arc::new(signer), args.listen, args.tls_dir).await?;
    Ok(())
}

/// Key generation mode: form (or resume) the group, run the ceremony, write public.json.
async fn run_dkg(args: &Args) -> Result<()> {
    use std::str::FromStr;
    let roster_path = args.roster.as_ref().context("--dkg needs --roster")?;
    anyhow::ensure!(!args.relays.is_empty(), "--dkg needs at least one --relay");
    anyhow::ensure!(!args.public.exists(), "{} exists; refusing to overwrite a keyset", args.public.display());
    let roster: Roster = read_json(roster_path).with_context(|| format!("reading {}", roster_path.display()))?;
    let n = roster.guardians.len() as u16;
    anyhow::ensure!(args.t >= 1 && args.t <= n, "need 1 <= t <= n (n = {n} guardians in the roster)");
    let mut by_key = HashMap::new();
    for g in &roster.guardians {
        let pk = NostrPublicKey::parse(&g.npub).with_context(|| format!("guardian {} npub", g.index))?;
        anyhow::ensure!(by_key.insert(pk, g.index).is_none(), "duplicate npub in roster");
    }
    let mut indices: Vec<Idx> = roster.guardians.iter().map(|g| g.index).collect();
    indices.sort_unstable();
    anyhow::ensure!(indices.iter().copied().eq(1..=n), "roster indices must be 1..={n}");

    let keys = load_or_create_keys(&args.keys)?;
    let node = MarmotNode::start(NodeConfig {
        keys: keys.clone(),
        relays: args.relays.clone(),
        storage: Storage::File(args.db.clone().unwrap_or_else(|| args.keys.with_extension("mls.sqlite"))),
        role: Role::Coordinator {
            guardians: roster.guardians.iter().map(|g| NostrPublicKey::parse(&g.npub)).collect::<Result<_, _>>()?,
        },
    })
    .await?;
    info!(npub = %keys.public_key().to_bech32()?, "key generation: waiting for the guardian group");
    anyhow::ensure!(node.wait_ready(Duration::from_secs(600)).await, "guardian group not ready after 10 minutes");
    info!("guardian group ready");
    let hub = Hub::start(node.clone(), String::new(), by_key);
    let params = dkg::Params {
        t: args.t,
        n,
        unit: cdk_common::CurrencyUnit::from_str(&args.unit).context("unknown unit")?,
        input_fee_ppk: args.input_fee_ppk,
        amounts: splitnut_core::keyfile::default_amounts(args.max_order),
    };
    let req = request_counter().load(std::sync::atomic::Ordering::Relaxed);
    let keyset = dkg::run(hub, &indices, &params, req, Duration::from_secs(120)).await?;
    if let Some(dir) = args.public.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&args.public, serde_json::to_vec_pretty(&keyset)?)?;
    info!(keyset = %keyset.keyset_id, public = %args.public.display(), "key generation done");
    println!("keyset {} ({} amounts, unit {}, fee {} ppk), {}-of-{}, by distributed key generation",
        keyset.keyset_id, keyset.keys.len(), keyset.unit, keyset.input_fee_ppk, keyset.t, keyset.n);
    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok(())
}
