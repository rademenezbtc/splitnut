//! What a guardian agrees to sign, given the operation context cdk-mintd passes down.
//!
//! A guardian releases its round-1 share only for an operation it can justify itself, without
//! trusting the mint host or the coordinator. (Round 1 already reveals `k_i·B'`, so this is the
//! point of no return, and everything is checked and recorded here.)
//!
//! * **Swap**: every input carries evidence (t partial evaluations with DLEQs) that it is
//!   validly signed, which this guardian checks against the public shares. No input may be
//!   spent by another operation, and outputs ≤ inputs − fees. Swaps therefore cannot create
//!   ecash, whoever runs the mint.
//! * **Melt** (signing change): the same input checks, and change ≤ inputs − fees − the amount
//!   paid out. For a bolt11 request, the amount must cover the invoice.
//! * **Mint**: outputs ≤ what the quotes have been paid minus what this guardian already helped
//!   issue against them; a bolt11 payment hash backs one quote only; the hourly cap applies.
//!   Payment itself cannot be proven to a guardian (the mint made the invoice), so new issuance
//!   is capped and counted rather than verified.
//! * **No context** (a stock cdk-mintd): refused, unless the guardian runs with
//!   `--allow-contextless`, which keeps the v1 behaviour (cap every signature).
//!
//! Every rule violation starts with `refused:`, so the coordinator can tell a refusal from an
//! outage.

use std::collections::BTreeSet;
use std::str::FromStr;

use cashu::Bolt11Invoice;
use sha2::{Digest, Sha256};
use splitnut_core::keyfile::{point_hex, to_hex_point, PublicKeyset};
use splitnut_core::{conv, verify, Idx};
use splitnut_proto::{partial_from_wire, WireInput, WireOp, WireQuote, WireSignItem};

use crate::ledger::Ledger;

pub struct Rules {
    keyset: PublicKeyset,
    allow_contextless: bool,
}

/// An input that passed its evidence check.
#[derive(Clone, Debug)]
pub struct CheckedInput {
    pub y: String,
    pub amount: u64,
}

fn refused(msg: impl Into<String>) -> String {
    format!("refused: {}", msg.into())
}

fn db(e: rusqlite::Error) -> String {
    format!("ledger error: {e}")
}

/// Canonical hash of an output set: sorted `amount:B'` lines.
pub fn outputs_hash<'a>(outputs: impl IntoIterator<Item = (u64, &'a str)>) -> String {
    let mut lines: Vec<String> = outputs.into_iter().map(|(a, b)| format!("{a}:{}", b.to_lowercase())).collect();
    lines.sort();
    hex::encode(Sha256::digest(lines.join("\n").as_bytes()))
}

/// A swap is identified by its set of inputs.
pub fn swap_op(ys: &[String]) -> String {
    let mut ys = ys.to_vec();
    ys.sort();
    format!("swap:{}", hex::encode(Sha256::digest(ys.join("\n").as_bytes())))
}

/// Count approved outputs as issued (keyed by `B'`, so retries, peers' approvals and the
/// coordinator's announcement all count once). Counting at approval, not on the coordinator's
/// announcement, means a coordinator that stays quiet cannot make issuance look smaller.
fn record_outputs(ledger: &Ledger, items: &[WireSignItem], now: u64) -> Result<(), String> {
    let outs: Vec<(String, u64)> = items.iter().map(|i| (i.b.to_lowercase(), i.amount)).collect();
    ledger.record_issued(&outs, now).map_err(db)?;
    Ok(())
}

fn melt_op(quote_id: &str) -> String {
    format!("melt:{quote_id}")
}

fn mint_op(quotes: &[WireQuote]) -> String {
    let ids: BTreeSet<&str> = quotes.iter().map(|q| q.id.as_str()).collect();
    format!("mint:{}", ids.into_iter().collect::<Vec<_>>().join(","))
}

impl Rules {
    pub fn new(keyset: PublicKeyset, allow_contextless: bool) -> Self {
        Self { keyset, allow_contextless }
    }

    fn fee(&self, inputs: usize) -> u64 {
        (inputs as u64 * self.keyset.input_fee_ppk).div_ceil(1000)
    }

    /// Amount of a bolt11 invoice in the keyset's unit, rounded up; `None` if this is not a
    /// bolt11 invoice, has no amount, or the unit is not sat/msat.
    fn invoice(&self, request: &str) -> Option<(String, Option<u64>)> {
        let inv = Bolt11Invoice::from_str(request).ok()?;
        let hash = inv.payment_hash().to_string();
        let amount = inv.amount_milli_satoshis().and_then(|msat| match self.keyset.unit.as_str() {
            "sat" => Some(msat.div_ceil(1000)),
            "msat" => Some(msat),
            _ => None,
        });
        Some((hash, amount))
    }

    /// Check one input's evidence: t distinct guardians' partials, each with a valid DLEQ
    /// against its public share, combining to the proof's `C`.
    pub fn check_input(&self, input: &WireInput) -> Result<CheckedInput, String> {
        let y = conv::hash_to_curve(input.secret.as_bytes()).map_err(|e| refused(format!("input secret: {e}")))?;
        let y_hex = to_hex_point(&y).map_err(|e| refused(e.to_string()))?;
        let c = point_hex(&input.c).map_err(|_| refused("input C is not a point"))?;
        let shares = self
            .keyset
            .public_shares_for(input.amount)
            .map_err(|_| refused(format!("input amount {} is not in the keyset", input.amount)))?;
        let mut parts = Vec::with_capacity(input.evidence.len());
        let mut seen = BTreeSet::new();
        for ev in &input.evidence {
            if !seen.insert(ev.i) {
                return Err(refused("input evidence repeats a guardian"));
            }
            parts.push((ev.i as Idx, partial_from_wire(&ev.partial).map_err(|e| refused(format!("input evidence: {e}")))?));
        }
        if parts.len() < self.keyset.t as usize {
            return Err(refused(format!(
                "input has evidence from {} guardians, {} needed",
                parts.len(),
                self.keyset.t
            )));
        }
        verify::combine_and_check(&c, &y, &shares, &parts)
            .map_err(|e| refused(format!("input is not validly signed ({e})")))?;
        Ok(CheckedInput { y: y_hex, amount: input.amount })
    }

    fn check_inputs(&self, inputs: &[WireInput]) -> Result<Vec<CheckedInput>, String> {
        if inputs.is_empty() {
            return Err(refused("operation has no inputs"));
        }
        let checked = inputs.iter().map(|i| self.check_input(i)).collect::<Result<Vec<_>, _>>()?;
        let unique: BTreeSet<&str> = checked.iter().map(|c| c.y.as_str()).collect();
        if unique.len() != checked.len() {
            return Err(refused("the same input appears twice"));
        }
        Ok(checked)
    }

    /// Refuse if any `y` is already spent by an operation other than `op`.
    fn check_unspent(&self, ledger: &Ledger, ys: &[&str], op: &str) -> Result<(), String> {
        for y in ys {
            match ledger.spent_by(y).map_err(db)? {
                Some(by) if by != op => {
                    ledger.note_double_spend(y).map_err(db)?;
                    let by = if by.is_empty() { "an earlier operation".to_string() } else { by };
                    return Err(refused(format!("input {}… already spent by {by}: double spend", &y[..12.min(y.len())])));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Refuse if `op` was already signed for a different output set.
    fn check_same_outputs(&self, ledger: &Ledger, op: &str, hash: &str, what: &str) -> Result<(), String> {
        let recorded = ledger.op_outputs(op).map_err(db)?;
        if recorded.iter().any(|h| h != hash) {
            return Err(refused(format!("{what} were already signed for different outputs")));
        }
        Ok(())
    }

    /// Decide on round 1 of a signing request and, if approved, record it.
    pub fn approve_sign(&self, ledger: &Ledger, items: &[WireSignItem], context: Option<&WireOp>, now: u64) -> Result<(), String> {
        let total: u64 = items.iter().map(|i| i.amount).sum();
        let hash = outputs_hash(items.iter().map(|i| (i.amount, i.b.as_str())));
        match context {
            None => {
                if !self.allow_contextless {
                    return Err(refused(
                        "no operation context: this guardian signs only operations it can check \
                         (run cdk-mintd with operation context, or start the guardian with --allow-contextless)",
                    ));
                }
                ledger.check_cap(total, now).map_err(refused)?;
                ledger.record_signed(0, total, now).map_err(db)?;
                Ok(())
            }
            Some(WireOp::Swap { inputs }) => {
                let checked = self.check_inputs(inputs)?;
                let ys: Vec<String> = checked.iter().map(|c| c.y.clone()).collect();
                let op = swap_op(&ys);
                self.check_same_outputs(ledger, &op, &hash, "these inputs")?;
                self.check_unspent(ledger, &ys.iter().map(String::as_str).collect::<Vec<_>>(), &op)?;
                let total_in: u64 = checked.iter().map(|c| c.amount).sum();
                let fee = self.fee(checked.len());
                if total > total_in.saturating_sub(fee) {
                    return Err(refused(format!(
                        "swap outputs ({total}) exceed inputs ({total_in}) minus fees ({fee})"
                    )));
                }
                for c in &checked {
                    ledger.record_spend(&c.y, c.amount, &op, true, now).map_err(db)?;
                }
                ledger.record_op(&op, &hash, total, now).map_err(db)?;
                record_outputs(ledger, items, now)?;
                Ok(())
            }
            Some(WireOp::Melt { quote_id, amount, request, inputs }) => {
                let checked = self.check_inputs(inputs)?;
                let op = melt_op(quote_id);
                self.check_same_outputs(ledger, &op, &hash, "change for this melt")?;
                self.check_unspent(ledger, &checked.iter().map(|c| c.y.as_str()).collect::<Vec<_>>(), &op)?;
                if let Some((_, Some(invoice))) = self.invoice(request) {
                    if *amount < invoice {
                        return Err(refused(format!("melt pays {amount} but its invoice is for {invoice}")));
                    }
                }
                let total_in: u64 = checked.iter().map(|c| c.amount).sum();
                let fee = self.fee(checked.len());
                let max_change = total_in.saturating_sub(fee).saturating_sub(*amount);
                if total > max_change {
                    return Err(refused(format!(
                        "melt change ({total}) exceeds inputs ({total_in}) minus fees ({fee}) minus the amount paid ({amount})"
                    )));
                }
                for c in &checked {
                    ledger.record_spend(&c.y, c.amount, &op, true, now).map_err(db)?;
                }
                ledger.record_op(&op, &hash, total, now).map_err(db)?;
                record_outputs(ledger, items, now)?;
                Ok(())
            }
            Some(WireOp::Mint { quotes }) => {
                if quotes.is_empty() {
                    return Err(refused("issuance names no mint quote"));
                }
                let ids: BTreeSet<&str> = quotes.iter().map(|q| q.id.as_str()).collect();
                if ids.len() != quotes.len() {
                    return Err(refused("the same quote appears twice"));
                }
                let op = mint_op(quotes);
                if ledger.op_outputs(&op).map_err(db)?.contains(&hash) {
                    return Ok(()); // a retry of an issuance already approved and counted
                }
                let mut hashes = vec![];
                for q in quotes {
                    if let Some((payment_hash, invoice)) = self.invoice(&q.request) {
                        if let Some(amount) = invoice {
                            if q.amount_paid > amount {
                                return Err(refused(format!(
                                    "quote {} claims {} paid but its invoice is for {amount}",
                                    q.id, q.amount_paid
                                )));
                            }
                        }
                        if let Some(other) = ledger.quote_for_payment_hash(&payment_hash).map_err(db)? {
                            if other != q.id {
                                return Err(refused(format!(
                                    "quote {} reuses the invoice of quote {other}",
                                    q.id
                                )));
                            }
                        }
                        hashes.push((q.id.clone(), payment_hash));
                    }
                }
                let remaining: Vec<(String, u64)> = quotes
                    .iter()
                    .map(|q| (q.id.clone(), q.amount_paid.saturating_sub(ledger.quote_issued(&q.id))))
                    .collect();
                let allowed: u64 = remaining.iter().map(|(_, r)| r).sum();
                if total > allowed {
                    return Err(refused(format!(
                        "issuance ({total}) exceeds what its quotes were paid and have not yet been issued ({allowed})"
                    )));
                }
                ledger.check_cap(total, now).map_err(refused)?;
                self.record_mint(ledger, &op, &hash, total, &remaining, &hashes, now)?;
                ledger.record_signed(0, total, now).map_err(db)?;
                record_outputs(ledger, items, now)?;
                Ok(())
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_mint(
        &self,
        ledger: &Ledger,
        op: &str,
        hash: &str,
        total: u64,
        remaining: &[(String, u64)],
        hashes: &[(String, String)],
        now: u64,
    ) -> Result<(), String> {
        ledger.record_op(op, hash, total, now).map_err(db)?;
        let mut left = total;
        for (id, r) in remaining {
            let take = left.min(*r);
            if take > 0 {
                ledger.add_quote_issued(id, take).map_err(db)?;
                left -= take;
            }
        }
        if left > 0 {
            // Only from an announcement whose issuance exceeds what this guardian thinks the
            // quotes allow (it missed a payment update); count it against the first quote.
            if let Some((id, _)) = remaining.first() {
                ledger.add_quote_issued(id, left).map_err(db)?;
            }
        }
        for (id, h) in hashes {
            ledger.pin_payment_hash(id, h).map_err(db)?;
        }
        Ok(())
    }

    /// Decide on a proof-check request. The items are the operation's inputs; `ys` are their
    /// `Y` (hex) and amounts. A melt's spends are recorded here, unverified until evidence
    /// arrives; a swap's are recorded when its outputs are signed.
    pub fn approve_verify(&self, ledger: &Ledger, ys: &[(String, u64)], context: Option<&WireOp>, now: u64) -> Result<(), String> {
        let refs: Vec<&str> = ys.iter().map(|(y, _)| y.as_str()).collect();
        match context {
            None => {
                if self.allow_contextless {
                    // v1 behaviour: count each proof checked once.
                    ledger.record_redeemed(ys, now).map_err(db)?;
                }
                Ok(())
            }
            Some(WireOp::Swap { .. }) => {
                let op = swap_op(&ys.iter().map(|(y, _)| y.clone()).collect::<Vec<_>>());
                self.check_unspent(ledger, &refs, &op)
            }
            Some(WireOp::Melt { quote_id, .. }) => {
                let op = melt_op(quote_id);
                self.check_unspent(ledger, &refs, &op)?;
                for (y, amount) in ys {
                    ledger.record_spend(y, *amount, &op, false, now).map_err(db)?;
                }
                Ok(())
            }
            Some(WireOp::Mint { .. }) => Err(refused("a proof check cannot be part of an issuance")),
        }
    }

    /// Another guardian approved a proof check for a melt: record the spends (unverified, as for
    /// our own approval) so they block reuse here too.
    pub fn apply_peer_verify(&self, ledger: &Ledger, ys: &[(String, u64)], context: &WireOp, now: u64) -> Result<Option<String>, String> {
        let WireOp::Melt { quote_id, .. } = context else { return Ok(None) };
        let op = melt_op(quote_id);
        let mut conflict = None;
        for (y, amount) in ys {
            match ledger.spent_by(y).map_err(db)? {
                Some(by) if by != op => {
                    ledger.note_double_spend(y).map_err(db)?;
                    conflict = Some(format!("a peer approved {op} spending an input this guardian saw spent by {by}"));
                }
                _ => {
                    ledger.record_spend(y, *amount, &op, false, now).map_err(db)?;
                }
            }
        }
        Ok(conflict)
    }

    /// Apply an announcement of a finished operation (every guardian, signer or not). Returns
    /// a warning when the announced spends conflict with this guardian's records: the
    /// coordinator then got t other guardians to sign a double spend.
    pub fn apply_announcement(
        &self,
        ledger: &Ledger,
        outputs: &[(u64, String)],
        context: &WireOp,
        now: u64,
    ) -> Result<Option<String>, String> {
        let total: u64 = outputs.iter().map(|(a, _)| a).sum();
        let hash = outputs_hash(outputs.iter().map(|(a, b)| (*a, b.as_str())));
        let outs: Vec<(String, u64)> = outputs.iter().map(|(a, b)| (b.to_lowercase(), *a)).collect();
        ledger.record_issued(&outs, now).map_err(db)?;
        let (op, checked) = match context {
            WireOp::Mint { quotes } => {
                let op = mint_op(quotes);
                if outputs.is_empty() || ledger.op_outputs(&op).map_err(db)?.contains(&hash) {
                    return Ok(None);
                }
                let remaining: Vec<(String, u64)> = quotes
                    .iter()
                    .map(|q| (q.id.clone(), q.amount_paid.saturating_sub(ledger.quote_issued(&q.id))))
                    .collect();
                let hashes: Vec<(String, String)> = quotes
                    .iter()
                    .filter_map(|q| self.invoice(&q.request).map(|(h, _)| (q.id.clone(), h)))
                    .collect();
                self.record_mint(ledger, &op, &hash, total, &remaining, &hashes, now)?;
                return Ok(None);
            }
            WireOp::Swap { inputs } => {
                let checked = self.check_inputs(inputs)?;
                (swap_op(&checked.iter().map(|c| c.y.clone()).collect::<Vec<_>>()), checked)
            }
            WireOp::Melt { quote_id, inputs, .. } => (melt_op(quote_id), self.check_inputs(inputs)?),
        };
        let mut conflict = None;
        for c in &checked {
            match ledger.spent_by(&c.y).map_err(db)? {
                Some(by) if by != op => {
                    ledger.note_double_spend(&c.y).map_err(db)?;
                    conflict = Some(format!("announced {op} spends an input this guardian saw spent by {by}"));
                }
                _ => {
                    ledger.record_spend(&c.y, c.amount, &op, true, now).map_err(db)?;
                }
            }
        }
        if !outputs.is_empty() {
            ledger.record_op(&op, &hash, total, now).map_err(db)?;
        }
        Ok(conflict)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use cashu::dhke;
    use cashu::secret::Secret;
    use cashu::CurrencyUnit;
    use rand_core::OsRng;
    use splitnut_core::guardian::{Guardian, VerifyItem};
    use splitnut_core::keyfile::deal;
    use splitnut_proto::{partial_to_wire, WireEvidence};

    use super::*;

    struct World {
        rules: Rules,
        guardians: BTreeMap<Idx, Guardian>,
        full_keys: BTreeMap<u64, cashu::SecretKey>,
    }

    /// A 2-of-3 keyset, plus the full keys so tests can make tokens as a single-key mint would.
    fn world() -> World {
        let (keyset, files) = deal(2, 3, &CurrencyUnit::Sat, 0, 8, &mut OsRng).unwrap();
        let guardians: BTreeMap<Idx, Guardian> = files.iter().map(|f| (f.index, Guardian::from_file(f).unwrap())).collect();
        // Recombine each amount's key from two share files (test only).
        let mut full_keys = BTreeMap::new();
        for amount in keyset.amounts() {
            let parts: Vec<(Idx, splitnut_core::Scalar)> =
                files.iter().take(2).map(|f| (f.index, f.parse_shares().unwrap()[&amount])).collect();
            let k = splitnut_core::shamir::combine_scalars(&parts).unwrap();
            full_keys.insert(amount, conv::secret_key(&k).unwrap());
        }
        World { rules: Rules::new(keyset, false), guardians, full_keys }
    }

    impl World {
        /// A valid token of `amount`, as a wallet would hold it, with evidence from guardians 1 and 2.
        fn input(&self, amount: u64) -> WireInput {
            let secret = Secret::generate();
            let (b, r) = dhke::blind_message(secret.as_bytes(), None).unwrap();
            let k = &self.full_keys[&amount];
            let c = dhke::unblind_message(&dhke::sign_message(k, &b).unwrap(), &r, &k.public_key()).unwrap();
            let y = conv::hash_to_curve(secret.as_bytes()).unwrap();
            let evidence = [1u16, 2]
                .iter()
                .map(|i| {
                    let p = self.guardians[i].verify(&[VerifyItem { amount, y }], &mut OsRng).unwrap()[0];
                    WireEvidence { i: *i, partial: partial_to_wire(&p).unwrap() }
                })
                .collect();
            WireInput { amount, secret: secret.to_string(), c: c.to_hex(), evidence }
        }
    }

    fn outputs(amounts: &[u64]) -> Vec<WireSignItem> {
        amounts
            .iter()
            .map(|a| {
                let (b, _) = dhke::blind_message(Secret::generate().as_bytes(), None).unwrap();
                WireSignItem { amount: *a, b: b.to_hex() }
            })
            .collect()
    }

    const NOW: u64 = 1_000_000;

    #[test]
    fn swap_must_balance_and_inputs_must_be_genuine() {
        let w = world();
        let l = Ledger::in_memory(0).unwrap();
        let inputs = vec![w.input(8), w.input(4)];

        // outputs worth more than the inputs: refused
        let err = w.rules.approve_sign(&l, &outputs(&[8, 8]), Some(&WireOp::Swap { inputs: inputs.clone() }), NOW).unwrap_err();
        assert!(err.contains("exceed inputs"), "{err}");

        // a forged input (C not signed by the mint key): refused
        let mut forged = w.input(8);
        forged.c = w.input(8).c;
        let err = w.rules.approve_sign(&l, &outputs(&[8]), Some(&WireOp::Swap { inputs: vec![forged] }), NOW).unwrap_err();
        assert!(err.contains("not validly signed"), "{err}");

        // evidence from a single guardian is not enough
        let mut thin = w.input(4);
        thin.evidence.truncate(1);
        let err = w.rules.approve_sign(&l, &outputs(&[4]), Some(&WireOp::Swap { inputs: vec![thin] }), NOW).unwrap_err();
        assert!(err.contains("2 needed"), "{err}");

        // balanced: approved, and the inputs are now redeemed
        let outs = outputs(&[8, 2, 2]);
        w.rules.approve_sign(&l, &outs, Some(&WireOp::Swap { inputs: inputs.clone() }), NOW).unwrap();
        assert_eq!(l.totals(NOW).redeemed, 12);

        // a retry with the same outputs is fine and does not count twice
        w.rules.approve_sign(&l, &outs, Some(&WireOp::Swap { inputs: inputs.clone() }), NOW).unwrap();
        assert_eq!(l.totals(NOW).redeemed, 12);

        // the same inputs for other outputs: refused
        let err = w.rules.approve_sign(&l, &outputs(&[8, 4]), Some(&WireOp::Swap { inputs: inputs.clone() }), NOW).unwrap_err();
        assert!(err.contains("already signed for different outputs"), "{err}");

        // one of them again, in another swap: a double spend
        let again = vec![inputs[0].clone(), w.input(4)];
        let err = w.rules.approve_sign(&l, &outputs(&[8, 4]), Some(&WireOp::Swap { inputs: again }), NOW).unwrap_err();
        assert!(err.contains("double spend"), "{err}");
        assert_eq!(l.totals(NOW).duplicates, 1);
    }

    #[test]
    fn melt_spends_block_later_swaps_and_change_is_bounded() {
        let w = world();
        let l = Ledger::in_memory(0).unwrap();
        let inputs = vec![w.input(64), w.input(32)];
        let ys: Vec<(String, u64)> = inputs.iter().map(|i| (w.rules.check_input(i).unwrap().y, i.amount)).collect();
        let melt = |inputs: Vec<WireInput>| WireOp::Melt { quote_id: "mq1".into(), amount: 80, request: "custom".into(), inputs };

        // the proof check for the melt records the spends (unverified: not yet redeemed)
        w.rules.approve_verify(&l, &ys, Some(&melt(vec![])), NOW).unwrap();
        assert_eq!(l.totals(NOW).redeemed, 0);

        // so the same proofs cannot then be swapped
        let err = w.rules.approve_verify(&l, &ys, Some(&WireOp::Swap { inputs: vec![] }), NOW).unwrap_err();
        assert!(err.contains("double spend"), "{err}");
        let err = w.rules.approve_sign(&l, &outputs(&[64, 32]), Some(&WireOp::Swap { inputs: inputs.clone() }), NOW).unwrap_err();
        assert!(err.contains("double spend"), "{err}");

        // change is at most 96 - 80 = 16
        let err = w.rules.approve_sign(&l, &outputs(&[16, 8]), Some(&melt(inputs.clone())), NOW).unwrap_err();
        assert!(err.contains("melt change"), "{err}");
        w.rules.approve_sign(&l, &outputs(&[16]), Some(&melt(inputs.clone())), NOW).unwrap();
        // with evidence the spends are verified, so they now count as redeemed
        assert_eq!(l.totals(NOW).redeemed, 96);
    }

    #[test]
    fn issuance_is_bounded_by_quotes_and_capped() {
        let w = world();
        let l = Ledger::in_memory(1000).unwrap();
        let quote = |id: &str, paid: u64| WireQuote { id: id.into(), amount_paid: paid, amount_issued: 0, request: "custom".into() };
        let mint = |qs: Vec<WireQuote>| WireOp::Mint { quotes: qs };

        let err = w.rules.approve_sign(&l, &outputs(&[128, 1]), Some(&mint(vec![quote("q1", 128)])), NOW).unwrap_err();
        assert!(err.contains("exceeds what its quotes were paid"), "{err}");

        let outs = outputs(&[128]);
        w.rules.approve_sign(&l, &outs, Some(&mint(vec![quote("q1", 128)])), NOW).unwrap();
        // retry: fine; another issuance against the same, fully issued quote: refused
        w.rules.approve_sign(&l, &outs, Some(&mint(vec![quote("q1", 128)])), NOW).unwrap();
        let err = w.rules.approve_sign(&l, &outputs(&[128]), Some(&mint(vec![quote("q1", 128)])), NOW).unwrap_err();
        assert!(err.contains("(0)"), "{err}");

        // the hourly cap still applies to new money
        let err = w.rules.approve_sign(&l, &outputs(&[128; 8]), Some(&mint(vec![quote("q2", 1024)])), NOW).unwrap_err();
        assert!(err.contains("hourly issuance cap"), "{err}");
    }

    #[test]
    fn no_context_is_refused_unless_allowed() {
        let w = world();
        let l = Ledger::in_memory(0).unwrap();
        let err = w.rules.approve_sign(&l, &outputs(&[8]), None, NOW).unwrap_err();
        assert!(err.starts_with("refused: no operation context"), "{err}");
        let legacy = Rules::new(w.rules.keyset.clone(), true);
        legacy.approve_sign(&l, &outputs(&[8]), None, NOW).unwrap();
    }

    #[test]
    fn announcements_bring_non_signers_up_to_date() {
        let w = world();
        let signer = Ledger::in_memory(0).unwrap();
        let bystander = Ledger::in_memory(0).unwrap();
        let inputs = vec![w.input(8)];
        let outs = outputs(&[8]);
        let swap = WireOp::Swap { inputs: inputs.clone() };
        w.rules.approve_sign(&signer, &outs, Some(&swap), NOW).unwrap();

        let announced: Vec<(u64, String)> = outs.iter().map(|o| (o.amount, o.b.clone())).collect();
        for l in [&signer, &bystander] {
            assert_eq!(w.rules.apply_announcement(l, &announced, &swap, NOW).unwrap(), None);
            assert_eq!(l.totals(NOW).redeemed, 8, "counted once, signer or not");
        }
        // the bystander now refuses to sign a double spend of that input
        let err = w.rules.approve_sign(&bystander, &outputs(&[8]), Some(&WireOp::Swap { inputs: vec![inputs[0].clone()] }), NOW);
        assert!(err.is_err());
    }
}
