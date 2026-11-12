//! A compromised mint host, attacking the guardians.
//!
//! Connects to the coordinator exactly as cdk-mintd does (same gRPC API, same mTLS client
//! certificate) and tries what an attacker who controls the mint server could: sign without
//! context, over-issue against a quote, swap for more than the inputs, swap forged or spent
//! inputs, and swap proofs that a melt already spent. Each attempt must be refused, except one:
//! claiming a mint quote was paid. Guardians cannot see Lightning payments, so that is accepted
//! within the hourly cap and recorded in their ledgers. That is the remaining trust in v2, and
//! the run says so.
//!
//!   cargo run --example evil_mintd -- --tls-dir .m4/certs [--port 15060]
//!
//! Exits non-zero if any attempt does not end as expected.

use std::path::PathBuf;

use anyhow::{Context, Result};
use cdk_common::dhke;
use cdk_common::secret::Secret;
use cdk_common::{Amount, BlindSignature, BlindedMessage, Id, Proof, PublicKey, SecretKey};
use cdk_signatory::SignatoryRpcClient;
use cdk_signatory::signatory::{MintQuoteContext, OperationContext, Signatory};
use clap::Parser;

#[derive(Parser)]
#[command(about = "Attack the SplitNut guardians as a compromised mint host would")]
struct Args {
    /// Directory with the client certificate cdk-mintd uses
    #[arg(long)]
    tls_dir: PathBuf,
    #[arg(long, default_value = "127.0.0.1")]
    addr: String,
    #[arg(long, default_value_t = 15060)]
    port: u16,
}

struct Mint {
    client: SignatoryRpcClient,
    id: Id,
    keys: std::collections::BTreeMap<u64, PublicKey>,
}

struct Pending {
    msgs: Vec<BlindedMessage>,
    secrets: Vec<(Secret, SecretKey)>,
}

impl Mint {
    fn outputs(&self, amounts: &[u64]) -> Pending {
        let mut msgs = vec![];
        let mut secrets = vec![];
        for a in amounts {
            let secret = Secret::generate();
            let (b, r) = dhke::blind_message(secret.as_bytes(), None).expect("blind");
            msgs.push(BlindedMessage::new(Amount::from(*a), self.id, b));
            secrets.push((secret, r));
        }
        Pending { msgs, secrets }
    }

    fn unblind(&self, p: &Pending, sigs: &[BlindSignature]) -> Vec<Proof> {
        p.msgs
            .iter()
            .zip(&p.secrets)
            .zip(sigs)
            .map(|((m, (secret, r)), sig)| {
                let k = self.keys[&u64::from(m.amount)];
                let c = dhke::unblind_message(&sig.c, r, &k).expect("unblind");
                Proof::new(m.amount, self.id, secret.clone(), c)
            })
            .collect()
    }

    async fn sign(&self, p: &Pending, ctx: Option<OperationContext>) -> Result<Vec<Proof>, String> {
        match self.client.blind_sign_with_context(p.msgs.clone(), ctx).await {
            Ok(sigs) => Ok(self.unblind(p, &sigs)),
            Err(e) => Err(e.to_string()),
        }
    }
}

fn quote(id: &str, paid: u64) -> OperationContext {
    OperationContext::Mint {
        quotes: vec![MintQuoteContext {
            quote_id: id.to_string(),
            amount_paid: Amount::from(paid),
            amount_issued: Amount::from(0),
            request: "no invoice: the attacker just claims payment".to_string(),
        }],
    }
}

fn swap(inputs: &[Proof]) -> Option<OperationContext> {
    Some(OperationContext::Swap { inputs: inputs.to_vec() })
}

struct Score {
    failures: usize,
}

impl Score {
    /// `want_ok`: the attempt is expected to succeed (only the residual-trust case).
    fn check<T>(&mut self, n: usize, what: &str, r: &Result<T, String>, want_ok: bool) {
        let short = |e: &str| {
            let e = e.split("SplitNut ").last().unwrap_or(e);
            e.chars().take(170).collect::<String>()
        };
        match (r, want_ok) {
            (Err(e), false) => println!("  {n}. {what}\n     REFUSED  {}", short(e)),
            (Ok(_), true) => println!("  {n}. {what}\n     accepted (expected: see note)"),
            (Ok(_), false) => {
                println!("  {n}. {what}\n     FAIL: the guardians signed it");
                self.failures += 1;
            }
            (Err(e), true) => {
                println!("  {n}. {what}\n     FAIL: refused: {}", short(e));
                self.failures += 1;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let client = SignatoryRpcClient::new(&args.addr, args.port, Some(args.tls_dir))
        .await
        .context("connecting to the coordinator as cdk-mintd")?;
    let ks = client.keysets().await?;
    let keyset = ks.keysets.first().context("no keyset")?;
    let keys = keyset.keys.iter().map(|(a, k)| (u64::from(*a), *k)).collect();
    let m = Mint { client, id: keyset.id, keys };
    let run = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let mut score = Score { failures: 0 };
    println!("== a compromised mint host attacks the guardians (keyset {})", m.id);

    // 1. Sign with no context, as stock cdk-mintd (or a script) would.
    let r = m.sign(&m.outputs(&[512, 512]), None).await;
    score.check(1, "sign 1024 sat with no operation context", &r, false);

    // 2. Claim a quote was paid: guardians cannot check Lightning, so this is the residual trust.
    let q = format!("evil-{run}");
    let r = m.sign(&m.outputs(&[64]), Some(quote(&q, 64))).await;
    score.check(2, "claim mint quote paid 64 sat and issue 64", &r, true);
    let p = match r {
        Ok(p) => p,
        Err(_) => anyhow::bail!("cannot continue without step 2's proofs"),
    };

    // 3. Issue against the same quote again.
    let r = m.sign(&m.outputs(&[64]), Some(quote(&q, 64))).await;
    score.check(3, "issue another 64 against the same, already issued quote", &r, false);

    // 4. Issue more than the quote says was paid.
    let r = m.sign(&m.outputs(&[64, 64]), Some(quote(&format!("evil-{run}-b"), 64))).await;
    score.check(4, "issue 128 against a quote paid 64", &r, false);

    // 5. Swap for more than the inputs are worth.
    let r = m.sign(&m.outputs(&[64, 64]), swap(&p)).await;
    score.check(5, "swap 64 sat of inputs for 128 sat of outputs", &r, false);

    // 6. Swap a forged input (C not made by the mint key).
    let mut forged = p[0].clone();
    forged.secret = Secret::generate();
    let r = m.sign(&m.outputs(&[64]), swap(&[forged])).await;
    score.check(6, "swap a forged input", &r, false);

    // 7. A fair swap: accepted (control).
    let r = m.sign(&m.outputs(&[32, 32]), swap(&p)).await;
    score.check(7, "fair swap 64 -> 32 + 32 (control)", &r, true);
    let q2 = r.unwrap_or_default();

    // 8. Spend the same inputs again.
    let r = m.sign(&m.outputs(&[32, 32]), swap(&p)).await;
    score.check(8, "swap the same inputs again for new outputs (double spend)", &r, false);

    // 9. Melt proofs, then try to swap them too.
    let melt = OperationContext::Melt {
        quote_id: format!("evil-melt-{run}"),
        amount: Amount::from(64),
        request: "lnbc...".to_string(),
        inputs: vec![],
    };
    let r = m.client.verify_proofs_with_context(q2.clone(), Some(melt)).await.map_err(|e| e.to_string());
    score.check(9, "melt 64 sat (pays out over Lightning)", &r, true);
    let r = m.sign(&m.outputs(&[64]), swap(&q2)).await;
    score.check(10, "swap the melted proofs (double spend)", &r, false);

    println!(
        "\n  Note: steps 2, 7 and 9 are accepted. 7 and 9 are fair; 2 is the remaining trust:\n  \
         guardians cannot see Lightning payments, so a claimed mint quote is believed, but only\n  \
         within the hourly cap, at most once per quote, and recorded in every guardian's ledger."
    );
    if score.failures > 0 {
        anyhow::bail!("{} attack(s) did not end as expected", score.failures);
    }
    Ok(())
}
