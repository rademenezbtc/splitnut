//! A guardian's own ledger of ecash issued and redeemed, and its hourly issuance cap.
//!
//! * **signed**: amounts this guardian released a round-2 share for. The hourly cap applies
//!   here, checked before signing.
//! * **issued**: outputs the coordinator announced after combining, counted only after this
//!   guardian has checked each signature's DLEQ against the public mint key. Deduplicated by
//!   blinded message `B'`.
//! * **redeemed**: proofs checked through this guardian, counted once per `Y`. A `Y` seen again
//!   (a double-spend attempt or a retry) is counted as a duplicate instead.
//!
//! `outstanding = issued − redeemed` is the ecash in circulation as this guardian sees it,
//! which anyone can compare with the mint's Lightning balance. A guardian that was offline
//! misses events, so its totals can lag the others'.

use std::path::Path;

use rusqlite::{params, Connection};
use serde::Serialize;

pub const HOUR_SECS: u64 = 3600;

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Totals {
    pub issued: u64,
    pub redeemed: u64,
    pub outstanding: i64,
    pub signed_last_hour: u64,
    pub cap_per_hour: u64,
    pub duplicates: u64,
}

pub struct Ledger {
    db: Connection,
    cap_per_hour: u64,
}

impl Ledger {
    pub fn open(path: &Path, cap_per_hour: u64) -> rusqlite::Result<Self> {
        Self::init(Connection::open(path)?, cap_per_hour)
    }

    #[cfg(test)]
    pub fn in_memory(cap_per_hour: u64) -> rusqlite::Result<Self> {
        Self::init(Connection::open_in_memory()?, cap_per_hour)
    }

    fn init(db: Connection, cap_per_hour: u64) -> rusqlite::Result<Self> {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS signed   (ts INTEGER NOT NULL, req INTEGER NOT NULL, amount INTEGER NOT NULL);
             CREATE INDEX IF NOT EXISTS signed_ts ON signed(ts);
             CREATE TABLE IF NOT EXISTS issued   (b TEXT PRIMARY KEY, amount INTEGER NOT NULL, ts INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS redeemed (y TEXT PRIMARY KEY, amount INTEGER NOT NULL, ts INTEGER NOT NULL, seen INTEGER NOT NULL DEFAULT 1);",
        )?;
        Ok(Self { db, cap_per_hour })
    }

    pub fn signed_since(&self, since: u64) -> u64 {
        self.db
            .query_row("SELECT COALESCE(SUM(amount), 0) FROM signed WHERE ts > ?1", params![since as i64], |r| r.get::<_, i64>(0))
            .map(|v| v as u64)
            .unwrap_or(0)
    }

    /// `Err(reason)` if signing `amount` more now would exceed the hourly cap (0 = no cap).
    pub fn check_cap(&self, amount: u64, now: u64) -> Result<(), String> {
        if self.cap_per_hour == 0 {
            return Ok(());
        }
        let used = self.signed_since(now.saturating_sub(HOUR_SECS));
        if used.saturating_add(amount) > self.cap_per_hour {
            return Err(format!(
                "hourly issuance cap: {used} of {} sat used in the last hour, request is {amount} sat",
                self.cap_per_hour
            ));
        }
        Ok(())
    }

    pub fn record_signed(&self, req: u64, amount: u64, now: u64) -> rusqlite::Result<()> {
        self.db.execute("INSERT INTO signed (ts, req, amount) VALUES (?1, ?2, ?3)", params![now as i64, req as i64, amount as i64])?;
        Ok(())
    }

    /// Record verified issued outputs `(B' hex, amount)`; returns the newly counted amount.
    pub fn record_issued(&self, outputs: &[(String, u64)], now: u64) -> rusqlite::Result<u64> {
        let mut added = 0;
        for (b, amount) in outputs {
            let n = self.db.execute(
                "INSERT OR IGNORE INTO issued (b, amount, ts) VALUES (?1, ?2, ?3)",
                params![b, *amount as i64, now as i64],
            )?;
            if n == 1 {
                added += amount;
            }
        }
        Ok(added)
    }

    /// Record checked proofs `(Y hex, amount)`; returns (newly redeemed amount, duplicates).
    pub fn record_redeemed(&self, proofs: &[(String, u64)], now: u64) -> rusqlite::Result<(u64, u64)> {
        let (mut added, mut dups) = (0, 0);
        for (y, amount) in proofs {
            let n = self.db.execute(
                "INSERT OR IGNORE INTO redeemed (y, amount, ts) VALUES (?1, ?2, ?3)",
                params![y, *amount as i64, now as i64],
            )?;
            if n == 1 {
                added += amount;
            } else {
                self.db.execute("UPDATE redeemed SET seen = seen + 1 WHERE y = ?1", params![y])?;
                dups += 1;
            }
        }
        Ok((added, dups))
    }

    pub fn totals(&self, now: u64) -> Totals {
        let sum = |sql: &str| self.db.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap_or(0);
        let issued = sum("SELECT COALESCE(SUM(amount), 0) FROM issued");
        let redeemed = sum("SELECT COALESCE(SUM(amount), 0) FROM redeemed");
        let duplicates = sum("SELECT COALESCE(SUM(seen - 1), 0) FROM redeemed");
        Totals {
            issued: issued as u64,
            redeemed: redeemed as u64,
            outstanding: issued - redeemed,
            signed_last_hour: self.signed_since(now.saturating_sub(HOUR_SECS)),
            cap_per_hour: self.cap_per_hour,
            duplicates: duplicates as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_window_and_totals() {
        let l = Ledger::in_memory(1000).unwrap();
        let t0 = 1_000_000;
        assert!(l.check_cap(1000, t0).is_ok());
        l.record_signed(1, 800, t0).unwrap();
        assert!(l.check_cap(200, t0 + 10).is_ok());
        let err = l.check_cap(201, t0 + 10).unwrap_err();
        assert!(err.contains("800 of 1000"), "{err}");
        // an hour later the window has moved on
        assert!(l.check_cap(1000, t0 + HOUR_SECS + 1).is_ok());

        assert_eq!(l.record_issued(&[("b1".into(), 512), ("b2".into(), 256)], t0).unwrap(), 768);
        assert_eq!(l.record_issued(&[("b1".into(), 512)], t0).unwrap(), 0, "same output counted once");
        assert_eq!(l.record_redeemed(&[("y1".into(), 256)], t0).unwrap(), (256, 0));
        assert_eq!(l.record_redeemed(&[("y1".into(), 256)], t0).unwrap(), (0, 1), "double spend is a duplicate");
        let t = l.totals(t0 + 10);
        assert_eq!((t.issued, t.redeemed, t.outstanding, t.duplicates, t.signed_last_hour), (768, 256, 512, 1, 800));
    }

    #[test]
    fn no_cap() {
        let l = Ledger::in_memory(0).unwrap();
        assert!(l.check_cap(u64::MAX / 2, 0).is_ok());
    }
}
