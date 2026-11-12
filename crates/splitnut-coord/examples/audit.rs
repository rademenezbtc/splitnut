//! Audit a SplitNut mint from the outside: fetch every guardian's signed ledger event from the
//! relays and compare them.
//!
//! Each guardian publishes its totals (issued, redeemed, outstanding) and a digest of exactly
//! which outputs and proofs it counted, signed with its own Nostr key. Anyone with the roster
//! (guardian npubs) can check that the guardians agree, and compare the outstanding ecash with
//! the mint's reserves. No access to the mint or the guardian group is needed.
//!
//!   cargo run -p splitnut-coord --example audit -- --roster roster.json --relay ws://127.0.0.1:7777
//!       [--keyset 01ab...] [--expect-outstanding 800] [--max-age-secs 120]
//!
//! Exits non-zero if guardians disagree, an expectation fails, or fewer than two report.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use nostr_sdk::prelude::*;
use splitnut_proto::{LEDGER_D_PREFIX, LEDGER_KIND};

#[derive(Parser)]
#[command(about = "Fetch and compare SplitNut guardians' public ledgers")]
struct Args {
    #[arg(long)]
    roster: PathBuf,
    #[arg(long = "relay", required = true)]
    relays: Vec<String>,
    /// Only this keyset (default: each guardian's latest)
    #[arg(long)]
    keyset: Option<String>,
    /// Fail unless every reporting guardian's outstanding equals this
    #[arg(long)]
    expect_outstanding: Option<i64>,
    /// Fail unless every guardian in the roster reports
    #[arg(long)]
    require_all: bool,
    /// Ignore ledger events older than this
    #[arg(long, default_value_t = 600)]
    max_age_secs: u64,
}

#[derive(serde::Deserialize)]
struct Roster {
    guardians: Vec<Entry>,
}

#[derive(serde::Deserialize)]
struct Entry {
    index: u16,
    npub: String,
}

#[derive(serde::Deserialize)]
struct Ledger {
    keyset: String,
    guardian: u16,
    issued: u64,
    redeemed: u64,
    outstanding: i64,
    digest: String,
    unit: String,
    #[serde(default)]
    double_spend_attempts: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let roster: Roster = serde_json::from_slice(&std::fs::read(&args.roster)?).context("reading roster")?;
    let by_key: BTreeMap<PublicKey, u16> =
        roster.guardians.iter().map(|g| Ok((PublicKey::parse(&g.npub)?, g.index))).collect::<Result<_>>()?;

    let client = Client::default();
    for r in &args.relays {
        client.add_relay(r.as_str()).await?;
    }
    client.connect().await;
    let mut filter = Filter::new().kind(Kind::Custom(LEDGER_KIND)).authors(by_key.keys().copied());
    if let Some(k) = &args.keyset {
        filter = filter.identifier(format!("{LEDGER_D_PREFIX}{k}"));
    }
    let events = client.fetch_events(filter, Duration::from_secs(10)).await?;

    // Latest valid event per guardian. fetch_events checks signatures; the author must be in
    // the roster and the payload must name the same guardian.
    let now = Timestamp::now().as_secs();
    let mut latest: BTreeMap<u16, (Timestamp, Ledger)> = BTreeMap::new();
    for e in events.into_iter() {
        let Some(&index) = by_key.get(&e.pubkey) else { continue };
        let Ok(l) = serde_json::from_str::<Ledger>(&e.content) else { continue };
        if l.guardian != index || now.saturating_sub(e.created_at.as_secs()) > args.max_age_secs {
            continue;
        }
        if latest.get(&index).is_none_or(|(t, _)| e.created_at > *t) {
            latest.insert(index, (e.created_at, l));
        }
    }

    println!("== public ledgers ({} of {} guardians reporting)", latest.len(), by_key.len());
    for g in &roster.guardians {
        match latest.get(&g.index) {
            Some((t, l)) => println!(
                "  guardian {}: issued {}, redeemed {}, outstanding {} {}, digest {}…, {} s old, keyset {}…, double-spend attempts {}",
                g.index,
                l.issued,
                l.redeemed,
                l.outstanding,
                l.unit,
                &l.digest[..12],
                now.saturating_sub(t.as_secs()),
                &l.keyset[..12.min(l.keyset.len())],
                l.double_spend_attempts
            ),
            None => println!("  guardian {}: no recent ledger", g.index),
        }
    }
    if args.require_all && latest.len() < by_key.len() {
        bail!("only {} of {} guardians reported", latest.len(), by_key.len());
    }
    if latest.len() < 2 {
        bail!("fewer than two guardians reporting: nothing to compare");
    }
    let first = &latest.values().next().expect("non-empty").1;
    let agree = latest.values().all(|(_, l)| l.keyset == first.keyset && l.outstanding == first.outstanding && l.digest == first.digest);
    if !agree {
        bail!("guardians disagree: some missed operations, or one is lying; compare their digests");
    }
    println!("  all reporting guardians agree: {} {} outstanding (identical digests)", first.outstanding, first.unit);
    if let Some(want) = args.expect_outstanding {
        if first.outstanding != want {
            bail!("outstanding {} does not match the expected {want}", first.outstanding);
        }
        println!("  matches the expected {want}");
    }
    println!("  compare with the mint's reserves: outstanding ecash must not exceed what the mint holds");
    Ok(())
}
