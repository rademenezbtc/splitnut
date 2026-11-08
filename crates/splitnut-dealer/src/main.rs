//! splitnut-dealer: run once at setup.
//!
//! Generates one secret key per amount, splits each t-of-n, and writes:
//! * `public.json`: the public keyset (V2 keyset id), identity key and every guardian's
//!   public shares, for the coordinator;
//! * `guardian-<i>.json`: guardian i's secret shares (mode 0600).
//!
//! Defaults match cdk-mintd's default unit config (sat, fee 0, amounts 2^0..2^31), so the
//! mint never asks the signer to rotate. Trusted dealer: delete the output directory's
//! guardian files once they have been handed out.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, ensure, Context, Result};
use cashu::nuts::nut00::CurrencyUnit;
use clap::Parser;
use rand_core::OsRng;
use splitnut_core::keyfile::deal;

#[derive(Parser)]
#[command(about = "Generate and split SplitNut mint keys (trusted dealer, run once)")]
struct Args {
    /// Threshold: guardians needed to sign
    #[arg(short, long, default_value_t = 2)]
    t: u16,
    /// Number of guardians
    #[arg(short, long, default_value_t = 3)]
    n: u16,
    /// Output directory
    #[arg(short, long, default_value = "shares")]
    out: PathBuf,
    /// Currency unit (must match the cdk-mintd payment backend unit)
    #[arg(long, default_value = "sat")]
    unit: String,
    /// Input fee in parts per thousand (must match cdk-mintd's input_fee_ppk)
    #[arg(long, default_value_t = 0)]
    input_fee_ppk: u64,
    /// Number of amounts: 2^0 .. 2^(max_order-1); cdk-mintd's default is 32
    #[arg(long, default_value_t = 32)]
    max_order: u32,
    /// Overwrite existing files
    #[arg(long)]
    force: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(args.t >= 1 && args.t <= args.n, "need 1 <= t <= n");
    ensure!((1..=64).contains(&args.max_order), "max_order must be 1..=64");
    let unit = CurrencyUnit::from_str(&args.unit).context("unknown unit")?;

    std::fs::create_dir_all(&args.out)?;
    let public_path = args.out.join("public.json");
    if public_path.exists() && !args.force {
        bail!("{} exists; pass --force to overwrite", public_path.display());
    }

    let (keyset, files) = deal(args.t, args.n, &unit, args.input_fee_ppk, args.max_order, &mut OsRng)?;
    let keyset_id = keyset.keyset_id.clone();

    write_file(&public_path, &serde_json::to_vec_pretty(&keyset)?, false)?;
    for file in &files {
        write_file(&args.out.join(format!("guardian-{}.json", file.index)), &serde_json::to_vec_pretty(file)?, true)?;
    }

    println!("keyset {keyset_id} ({} amounts, unit {unit}, fee {} ppk)", keyset.keys.len(), args.input_fee_ppk);
    println!("{}-of-{} shares written to {}", args.t, args.n, args.out.display());
    println!("hand each guardian-<i>.json to its guardian, then delete them here");
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| format!("writing {}", path.display()))?;
    f.write_all(bytes)?;
    Ok(())
}
