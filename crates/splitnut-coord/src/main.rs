//! splitnut-coord: the remote signer that cdk-mintd talks to.
//!
//! Implements CDK's `Signatory` trait ([`signer::ThresholdSigner`]) and serves it with CDK's
//! own generic `start_grpc_server`, so the gRPC schema, mTLS and version check are exactly
//! what cdk-mintd expects. Holds no key material: each `blind_sign` / `verify_proofs` call
//! goes to t-of-n guardians and every share is checked before combining.
//!
//! Milestone 2 runs the guardians in-process (`--local-guardian`); milestone 3 reaches them
//! over Marmot.

mod link;
mod signer;

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
use crate::signer::ThresholdSigner;

#[derive(Parser)]
#[command(about = "SplitNut coordinator: threshold remote signer for cdk-mintd")]
struct Args {
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();

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
    anyhow::ensure!(!guardians.is_empty(), "no guardians configured");

    let signer = ThresholdSigner::new(&keyset, guardians, Duration::from_millis(args.timeout_ms))?;
    info!(
        keyset = %keyset.keyset_id, t = keyset.t, n = keyset.n, offline = ?args.offline,
        "SplitNut coordinator ready (holds no key material)"
    );
    cdk_signatory::start_grpc_server(Arc::new(signer), args.listen, args.tls_dir).await?;
    Ok(())
}
