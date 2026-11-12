//! splitnut-relay: a small in-memory Nostr relay for development and demos, with a wire tap.
//!
//! Every event written to the relay passes through a policy hook that counts events and bytes
//! per kind and scans the content for SplitNut plaintext markers. With Marmot working, the
//! group traffic (kind 445) and welcomes (kind 1059) must show zero plaintext hits.
//!
//! Public relays work just as well; this one exists because some environments (CI, sandboxes)
//! cannot reach them, and because the tap makes "relays see only ciphertext" checkable.

use std::collections::{BTreeMap, VecDeque};
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
    /// Events each connection may publish per minute (public relays enforce similar limits)
    #[arg(long, default_value_t = 600)]
    notes_per_minute: u32,
    /// Serve wire-tap stats as JSON on this port (GET /stats), for the dashboard
    #[arg(long)]
    http_port: Option<u16>,
}

#[derive(Debug, Default, serde::Serialize)]
struct KindStats {
    events: u64,
    bytes: u64,
    plaintext_hits: u64,
}

/// What the relay stored, as an outsider sees it: kind, size and the start of the content.
#[derive(Debug, Clone, serde::Serialize)]
struct Seen {
    kind: u16,
    bytes: usize,
    id: String,
    content: String,
    plaintext: bool,
    ts: u64,
}

#[derive(Debug, Default)]
struct TapInner {
    kinds: BTreeMap<u16, KindStats>,
    recent: VecDeque<Seen>,
}

#[derive(Debug, Default, Clone)]
struct Tap(Arc<Mutex<TapInner>>);

impl WritePolicy for Tap {
    fn admit_event<'a>(&'a self, event: &'a Event, _addr: &'a SocketAddr) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            // Only private traffic must be ciphertext; guardians' ledger totals (kind 30078) are
            // public on purpose.
            let private = matches!(event.kind.as_u16(), 445 | 1059);
            let hit = private && PLAINTEXT_MARKERS.iter().any(|m| event.content.contains(m));
            let size = event.as_json().len();
            let mut tap = self.0.lock().unwrap();
            if tap.recent.len() == 20 {
                tap.recent.pop_front();
            }
            tap.recent.push_back(Seen {
                kind: event.kind.as_u16(),
                bytes: size,
                id: event.id.to_hex(),
                content: event.content.chars().take(96).collect(),
                plaintext: hit,
                ts: event.created_at.as_secs(),
            });
            let k = tap.kinds.entry(event.kind.as_u16()).or_default();
            k.events += 1;
            k.bytes += size as u64;
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
        30078 => "public ledger (signed, plaintext on purpose)",
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
        .write_policy(tap.clone())
        .rate_limit(RateLimit { max_reqs: 500, notes_per_minute: args.notes_per_minute });
    let relay = LocalRelay::new(builder);
    relay.run().await?;
    info!("relay listening on {}", relay.url().await);
    if let Some(port) = args.http_port {
        let tap = tap.clone();
        let addr = SocketAddr::new(args.addr, port);
        tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/stats",
                axum::routing::get(move || {
                    let tap = tap.clone();
                    async move {
                        let t = tap.0.lock().unwrap();
                        let kinds: BTreeMap<String, serde_json::Value> = t
                            .kinds
                            .iter()
                            .map(|(k, s)| (k.to_string(), serde_json::json!({ "name": kind_name(*k), "events": s.events, "bytes": s.bytes, "plaintext_hits": s.plaintext_hits })))
                            .collect();
                        let body = serde_json::json!({ "kinds": kinds, "recent": t.recent.iter().rev().collect::<Vec<_>>() });
                        ([(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], axum::Json(body))
                    }
                }),
            );
            match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => {
                    info!("wire-tap stats on http://{addr}/stats");
                    let _ = axum::serve(l, app).await;
                }
                Err(e) => tracing::error!("stats server: {e}"),
            }
        });
    }

    let mut last = String::new();
    loop {
        tokio::time::sleep(Duration::from_secs(args.report_secs)).await;
        let t = tap.0.lock().unwrap();
        let line = t
            .kinds
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
