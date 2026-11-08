//! splitnut-relay: a small in-memory Nostr relay for development and demos, with a wire tap.
//!
//! Every event written to the relay passes through a policy hook that counts events and bytes
//! per kind and scans the content for SplitNut plaintext markers. With Marmot working, the
//! group traffic (kind 445) and welcomes (kind 1059) must show zero plaintext hits.
//!
//! Public relays work just as well; this one exists because some environments (CI, sandboxes)
//! cannot reach them, and because the tap makes "relays see only ciphertext" checkable.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use nostr_relay_builder::prelude::*;
use tracing::info;

/// Strings that appear in SplitNut's plaintext wire messages. Seeing one on the relay would
/// mean something was published unencrypted.
const PLAINTEXT_MARKERS: &[&str] = &["\"req\"", "sign1", "sign2", "verify", "\"items\"", "splitnut"];

#[derive(Parser)]
#[command(about = "In-memory Nostr relay with a wire tap, for SplitNut development")]
struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    addr: IpAddr,
    #[arg(long, default_value_t = 7777)]
    port: u16,
    /// Seconds between wire-tap summaries in the log
    #[arg(long, default_value_t = 10)]
    report_secs: u64,
}

#[derive(Debug, Default)]
struct KindStats {
    events: u64,
    bytes: u64,
    plaintext_hits: u64,
}

#[derive(Debug, Default, Clone)]
struct Tap(Arc<Mutex<BTreeMap<u16, KindStats>>>);

impl WritePolicy for Tap {
    fn admit_event<'a>(&'a self, event: &'a Event, _addr: &'a SocketAddr) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            let hit = PLAINTEXT_MARKERS.iter().any(|m| event.content.contains(m));
            let mut stats = self.0.lock().unwrap();
            let k = stats.entry(event.kind.as_u16()).or_default();
            k.events += 1;
            k.bytes += event.as_json().len() as u64;
            if hit {
                k.plaintext_hits += 1;
                tracing::warn!(kind = event.kind.as_u16(), id = %event.id, "plaintext marker seen on the wire");
            }
            PolicyResult::Accept
        })
    }
}

fn kind_name(k: u16) -> &'static str {
    match k {
        443 | 30443 => "key package",
        445 => "group message",
        1059 => "gift wrap (welcome)",
        10051 => "key package relays",
        _ => "other",
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    let tap = Tap::default();
    let builder = RelayBuilder::default()
        .addr(args.addr)
        .port(args.port)
        .write_policy(tap.clone());
    let relay = LocalRelay::new(builder);
    relay.run().await?;
    info!("relay listening on {}", relay.url().await);

    let mut last = String::new();
    loop {
        tokio::time::sleep(Duration::from_secs(args.report_secs)).await;
        let stats = tap.0.lock().unwrap();
        let line = stats
            .iter()
            .map(|(k, s)| format!("{k} {}: {} events, {} B, {} plaintext", kind_name(*k), s.events, s.bytes, s.plaintext_hits))
            .collect::<Vec<_>>()
            .join(" | ");
        if !line.is_empty() && line != last {
            info!("wire tap: {line}");
            last = line;
        }
    }
}
