//! Percolator Strict-Serializable MVCC Engine + Linearizable Raw CAS Register Store.
//!
//! Enforces all critical invariants:
//! 1. Separate `rollbacks` (by `start_ts`), `committed_by_start_ts` (`start_ts -> commit_ts`),
//!    `writes` (by `commit_ts`, containing `Put | Delete | Lock`), `data` (by `start_ts`), and `lock`.
//! 2. `Prewrite`:
//!    - Rejects Zombie Prewrites if `rollbacks.contains(&start_ts)`
//!    - Idempotent `Ok` if already committed (`committed_by_start_ts`) or already locked by `start_ts`
//!    - Rejects with `KeyLocked` if locked by another transaction
//!    - Rejects with `WriteConflict` if any committed write (`Put | Delete | Lock`) has `commit_ts >= start_ts`
//! 3. `CheckTxnStatus`:
//!    - Uses ONLY deterministic `caller_current_ts` from the Raft command (zero local wall-clock usage!)
//!    - Writes permanent `rollbacks.insert(lock_start_ts)` on Primary when missing or TTL-expired
//! 4. Lossless snapshot serialization preserving full `rollbacks` & `writes` history so delayed RPCs
//!    arriving after `InstallSnapshot` remain 100% safe against Zombie Prewrite resurrection.

use std::collections::{BTreeMap, BTreeSet};

use crate::crc32::Crc32Hasher;
use crate::protocol::{
    ClientStatus, LockInfo, LockOp, Mutation, StateMachineCmd, TxnStatusAction,
};
use crate::wire::{ByteReader, ByteWriter, WireError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteKind {
    Put = 1,
    Delete = 2,
    Lock = 3,
}

impl WriteKind {
    fn from_u8(v: u8) -> Result<Self, WireError> {
        match v {
            1 => Ok(WriteKind::Put),
            2 => Ok(WriteKind::Delete),
            3 => Ok(WriteKind::Lock),
            tag => Err(WireError::InvalidEnumTag {
                context: "WriteKind",
                tag,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockRecord {
    pub start_ts: u64,
    pub primary_key: Vec<u8>,
    pub op: LockOp,
    pub ttl_ts: u64,
}

impl LockRecord {
    pub fn to_info(&self, key: &[u8]) -> LockInfo {
        LockInfo {
            key: key.to_vec(),
            primary_key: self.primary_key.clone(),
            start_ts: self.start_ts,
            ttl_ts: self.ttl_ts,
            op: self.op,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommittedWrite {
    pub start_ts: u64,
    pub kind: WriteKind,
}

#[derive(Debug, Clone, Default)]
pub struct KeyTimeline {
    pub lock: Option<LockRecord>,
    pub data: BTreeMap<u64, Vec<u8>>,
    pub writes: BTreeMap<u64, CommittedWrite>,
    pub committed_by_start_ts: BTreeMap<u64, u64>,
    pub rollbacks: BTreeSet<u64>,
}

#[derive(Debug, Clone)]
pub enum ReadOutcome {
    Value(Option<Vec<u8>>),
    Locked(LockInfo),
}

#[derive(Debug, Clone)]
pub enum ApplyResult {
    NoOp,
    Prewrite {
        status: ClientStatus,
        reason: String,
        blocking_lock: Option<LockInfo>,
    },
    Commit {
        status: ClientStatus,
        reason: String,
    },
    Rollback {
        status: ClientStatus,
    },
    CheckTxn {
        action: TxnStatusAction,
        commit_ts: u64,
    },
    RawCas {
        swapped: bool,
        prev_value: Option<Vec<u8>>,
    },
}

#[derive(Debug, Clone, Default)]
pub struct MvccStore {
    pub keys: BTreeMap<Vec<u8>, KeyTimeline>,
    pub raw_registers: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Deduplication table for linearizable RawCas (`op_uid -> (swapped, prev_value)`).
    pub cas_dedup: BTreeMap<u64, (bool, Option<Vec<u8>>)>,
}

impl MvccStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&mut self, cmd: &StateMachineCmd) -> ApplyResult {
        match cmd {
            StateMachineCmd::NoOp => ApplyResult::NoOp,
            StateMachineCmd::Prewrite {
                start_ts,
                primary_key,
                lock_ttl_ts,
                mutations,
            } => self.apply_prewrite(*start_ts, primary_key, *lock_ttl_ts, mutations),
            StateMachineCmd::Commit {
                start_ts,
                commit_ts,
                keys,
            } => self.apply_commit(*start_ts, *commit_ts, keys),
            StateMachineCmd::BatchRollback { start_ts, keys } => {
                self.apply_batch_rollback(*start_ts, keys)
            }
            StateMachineCmd::CheckTxnStatus {
                primary_key,
                lock_start_ts,
                caller_current_ts,
            } => self.apply_check_txn_status(primary_key, *lock_start_ts, *caller_current_ts),
            StateMachineCmd::RawCas {
                key,
                expected,
                desired,
                op_uid,
            } => self.apply_raw_cas(key, expected, desired, *op_uid),
        }
    }

    fn apply_prewrite(
        &mut self,
        start_ts: u64,
        primary_key: &[u8],
        lock_ttl_ts: u64,
        mutations: &[Mutation],
    ) -> ApplyResult {
        // Phase 1: Validate all mutations in this shard atomically before mutating state
        for m in mutations {
            if let Some(tl) = self.keys.get(&m.key) {
                // 1) Rolled-back check (blocks Zombie Prewrites permanently!)
                if tl.rollbacks.contains(&start_ts) {
                    return ApplyResult::Prewrite {
                        status: ClientStatus::TxnAborted,
                        reason: format!("start_ts={} already rolled back", start_ts),
                        blocking_lock: None,
                    };
                }
                // 2) Already committed idempotency check
                if tl.committed_by_start_ts.contains_key(&start_ts) {
                    continue;
                }
                // 3) Active lock check
                if let Some(ref existing_lock) = tl.lock {
                    if existing_lock.start_ts == start_ts {
                        // Idempotent retry of our own Prewrite
                        continue;
                    }
                    return ApplyResult::Prewrite {
                        status: ClientStatus::KeyLocked,
                        reason: format!(
                            "locked by start_ts={} (our start_ts={})",
                            existing_lock.start_ts, start_ts
                        ),
                        blocking_lock: Some(existing_lock.to_info(&m.key)),
                    };
                }
                // 4) Committed write conflict check (`writes` holds Put | Delete | Lock, never Rollback)
                if let Some((&latest_commit_ts, _)) = tl.writes.iter().next_back() {
                    if latest_commit_ts >= start_ts {
                        return ApplyResult::Prewrite {
                            status: ClientStatus::WriteConflict,
                            reason: format!(
                                "write_conflict: latest_commit_ts={} >= start_ts={}",
                                latest_commit_ts, start_ts
                            ),
                            blocking_lock: None,
                        };
                    }
                }
            }
        }

        // Phase 2: All checks passed -> acquire locks and stage values
        for m in mutations {
            let tl = self.keys.entry(m.key.clone()).or_default();
            if tl.committed_by_start_ts.contains_key(&start_ts) {
                continue;
            }
            if let Some(ref existing_lock) = tl.lock {
                if existing_lock.start_ts == start_ts {
                    continue;
                }
            }
            tl.lock = Some(LockRecord {
                start_ts,
                primary_key: primary_key.to_vec(),
                op: m.op,
                ttl_ts: lock_ttl_ts,
            });
            if m.op == LockOp::Put {
                tl.data
                    .insert(start_ts, m.value.clone().unwrap_or_default());
            }
        }

        ApplyResult::Prewrite {
            status: ClientStatus::Ok,
            reason: String::new(),
            blocking_lock: None,
        }
    }

    fn apply_commit(&mut self, start_ts: u64, commit_ts: u64, keys: &[Vec<u8>]) -> ApplyResult {
        if commit_ts <= start_ts {
            return ApplyResult::Commit {
                status: ClientStatus::BadRequest,
                reason: format!("commit_ts={} <= start_ts={}", commit_ts, start_ts),
            };
        }

        // Validate all keys in batch first
        for key in keys {
            let Some(tl) = self.keys.get(key) else {
                return ApplyResult::Commit {
                    status: ClientStatus::TxnAborted,
                    reason: "key timeline missing on commit".to_string(),
                };
            };
            if tl.rollbacks.contains(&start_ts) {
                return ApplyResult::Commit {
                    status: ClientStatus::TxnAborted,
                    reason: format!("start_ts={} already rolled back", start_ts),
                };
            }
            if tl.committed_by_start_ts.contains_key(&start_ts) {
                continue;
            }
            match &tl.lock {
                Some(l) if l.start_ts == start_ts => {}
                _ => {
                    return ApplyResult::Commit {
                        status: ClientStatus::TxnAborted,
                        reason: format!("active lock for start_ts={} missing on commit", start_ts),
                    };
                }
            }
        }

        // Commit all keys atomically
        for key in keys {
            let tl = self.keys.entry(key.clone()).or_default();
            if tl.committed_by_start_ts.contains_key(&start_ts) {
                continue;
            }
            if let Some(lock) = tl.lock.take() {
                let kind = match lock.op {
                    LockOp::Put => WriteKind::Put,
                    LockOp::Delete => WriteKind::Delete,
                    LockOp::ReadLock => WriteKind::Lock,
                };
                tl.writes
                    .insert(commit_ts, CommittedWrite { start_ts, kind });
                tl.committed_by_start_ts.insert(start_ts, commit_ts);
            }
        }

        ApplyResult::Commit {
            status: ClientStatus::Ok,
            reason: String::new(),
        }
    }

    fn apply_batch_rollback(&mut self, start_ts: u64, keys: &[Vec<u8>]) -> ApplyResult {
        for key in keys {
            let tl = self.keys.entry(key.clone()).or_default();
            // Never clobber an already committed transaction
            if tl.committed_by_start_ts.contains_key(&start_ts) {
                continue;
            }
            if tl.lock.as_ref().map_or(false, |l| l.start_ts == start_ts) {
                tl.lock = None;
                tl.data.remove(&start_ts);
            }
            tl.rollbacks.insert(start_ts);
        }
        ApplyResult::Rollback {
            status: ClientStatus::Ok,
        }
    }

    fn apply_check_txn_status(
        &mut self,
        primary_key: &[u8],
        lock_start_ts: u64,
        caller_current_ts: u64,
    ) -> ApplyResult {
        let tl = self.keys.entry(primary_key.to_vec()).or_default();

        if let Some(&commit_ts) = tl.committed_by_start_ts.get(&lock_start_ts) {
            return ApplyResult::CheckTxn {
                action: TxnStatusAction::AlreadyCommitted,
                commit_ts,
            };
        }

        if tl.rollbacks.contains(&lock_start_ts) {
            return ApplyResult::CheckTxn {
                action: TxnStatusAction::AlreadyRolledBack,
                commit_ts: 0,
            };
        }

        if let Some(ref lock) = tl.lock {
            if lock.start_ts == lock_start_ts {
                let expire_ts = lock.start_ts.saturating_add(lock.ttl_ts);
                if expire_ts <= caller_current_ts {
                    // Deterministic logical TTL expiration -> rollback Primary & leave tombstone
                    tl.lock = None;
                    tl.data.remove(&lock_start_ts);
                    tl.rollbacks.insert(lock_start_ts);
                    return ApplyResult::CheckTxn {
                        action: TxnStatusAction::TtlExpiredRolledBack,
                        commit_ts: 0,
                    };
                } else {
                    return ApplyResult::CheckTxn {
                        action: TxnStatusAction::LockAlive,
                        commit_ts: expire_ts,
                    };
                }
            }
        }

        // Primary has neither commit, rollback, nor active lock for `lock_start_ts`:
        // Write permanent Rollback tombstone so delayed Zombie Prewrite can never commit later!
        tl.rollbacks.insert(lock_start_ts);
        ApplyResult::CheckTxn {
            action: TxnStatusAction::MissingPrimaryRolledBack,
            commit_ts: 0,
        }
    }

    fn apply_raw_cas(
        &mut self,
        key: &[u8],
        expected: &Option<Vec<u8>>,
        desired: &[u8],
        op_uid: u64,
    ) -> ApplyResult {
        if let Some((swapped, prev)) = self.cas_dedup.get(&op_uid) {
            return ApplyResult::RawCas {
                swapped: *swapped,
                prev_value: prev.clone(),
            };
        }
        let current = self.raw_registers.get(key).cloned();
        let swapped = &current == expected;
        if swapped {
            self.raw_registers.insert(key.to_vec(), desired.to_vec());
        }
        self.cas_dedup.insert(op_uid, (swapped, current.clone()));
        ApplyResult::RawCas {
            swapped,
            prev_value: current,
        }
    }

    /// Snapshot-isolated / Linearizable MVCC read at `read_ts`.
    /// Must ONLY be invoked after Lease-free `ReadIndex` has confirmed leadership & `last_applied >= read_index`.
    pub fn read_at_ts(&self, key: &[u8], read_ts: u64) -> ReadOutcome {
        let Some(tl) = self.keys.get(key) else {
            return ReadOutcome::Value(None);
        };

        if let Some(ref lock) = tl.lock {
            // ReadLock never alters values, so readers safely skip ReadLock;
            // Put/Delete locks with start_ts <= read_ts MUST block/resolve!
            if lock.start_ts <= read_ts && lock.op != LockOp::ReadLock {
                return ReadOutcome::Locked(lock.to_info(key));
            }
        }

        for (_cts, cw) in tl.writes.range(..=read_ts).rev() {
            match cw.kind {
                WriteKind::Put => {
                    return ReadOutcome::Value(tl.data.get(&cw.start_ts).cloned());
                }
                WriteKind::Delete => {
                    return ReadOutcome::Value(None);
                }
                WriteKind::Lock => continue,
            }
        }

        ReadOutcome::Value(None)
    }

    pub fn raw_get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.raw_registers.get(key).cloned()
    }

    /// Deterministic CRC32 digest of the entire state machine (used to prove replica convergence!).
    pub fn state_crc32(&self) -> u32 {
        let bytes = self.encode_snapshot();
        let mut h = Crc32Hasher::new();
        h.update(&bytes);
        h.finalize()
    }

    /// Lossless binary snapshot of all MVCC timelines + raw registers + CAS deduplication table.
    pub fn encode_snapshot(&self) -> Vec<u8> {
        let mut w = ByteWriter::with_capacity(1024);
        w.put_u32(self.keys.len() as u32);
        for (key, tl) in &self.keys {
            w.put_bytes(key);
            match &tl.lock {
                Some(l) => {
                    w.put_bool(true);
                    w.put_u64(l.start_ts);
                    w.put_bytes(&l.primary_key);
                    w.put_u8(l.op as u8);
                    w.put_u64(l.ttl_ts);
                }
                None => w.put_bool(false),
            }
            w.put_u32(tl.data.len() as u32);
            for (&sts, val) in &tl.data {
                w.put_u64(sts);
                w.put_bytes(val);
            }
            w.put_u32(tl.writes.len() as u32);
            for (&cts, cw) in &tl.writes {
                w.put_u64(cts);
                w.put_u64(cw.start_ts);
                w.put_u8(cw.kind as u8);
            }
            w.put_u32(tl.committed_by_start_ts.len() as u32);
            for (&sts, &cts) in &tl.committed_by_start_ts {
                w.put_u64(sts);
                w.put_u64(cts);
            }
            w.put_u32(tl.rollbacks.len() as u32);
            for &sts in &tl.rollbacks {
                w.put_u64(sts);
            }
        }

        w.put_u32(self.raw_registers.len() as u32);
        for (k, v) in &self.raw_registers {
            w.put_bytes(k);
            w.put_bytes(v);
        }

        w.put_u32(self.cas_dedup.len() as u32);
        for (&uid, (swapped, prev)) in &self.cas_dedup {
            w.put_u64(uid);
            w.put_bool(*swapped);
            w.put_opt_bytes(prev);
        }

        w.into_vec()
    }

    pub fn decode_snapshot(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        let num_keys = r.get_u32("Snap.keys.len")? as usize;
        let mut keys = BTreeMap::new();

        for _ in 0..num_keys {
            let key = r.get_bytes("Snap.key")?;
            let lock = if r.get_bool("Snap.has_lock")? {
                Some(LockRecord {
                    start_ts: r.get_u64("Snap.lock.start_ts")?,
                    primary_key: r.get_bytes("Snap.lock.primary_key")?,
                    op: LockOp::from_u8(r.get_u8("Snap.lock.op")?)?,
                    ttl_ts: r.get_u64("Snap.lock.ttl_ts")?,
                })
            } else {
                None
            };

            let data_len = r.get_u32("Snap.data.len")? as usize;
            let mut data = BTreeMap::new();
            for _ in 0..data_len {
                let sts = r.get_u64("Snap.data.sts")?;
                let val = r.get_bytes("Snap.data.val")?;
                data.insert(sts, val);
            }

            let writes_len = r.get_u32("Snap.writes.len")? as usize;
            let mut writes = BTreeMap::new();
            for _ in 0..writes_len {
                let cts = r.get_u64("Snap.writes.cts")?;
                let sts = r.get_u64("Snap.writes.sts")?;
                let kind = WriteKind::from_u8(r.get_u8("Snap.writes.kind")?)?;
                writes.insert(cts, CommittedWrite { start_ts: sts, kind });
            }

            let cbs_len = r.get_u32("Snap.cbs.len")? as usize;
            let mut committed_by_start_ts = BTreeMap::new();
            for _ in 0..cbs_len {
                let sts = r.get_u64("Snap.cbs.sts")?;
                let cts = r.get_u64("Snap.cbs.cts")?;
                committed_by_start_ts.insert(sts, cts);
            }

            let rb_len = r.get_u32("Snap.rb.len")? as usize;
            let mut rollbacks = BTreeSet::new();
            for _ in 0..rb_len {
                rollbacks.insert(r.get_u64("Snap.rb.sts")?);
            }

            keys.insert(
                key,
                KeyTimeline {
                    lock,
                    data,
                    writes,
                    committed_by_start_ts,
                    rollbacks,
                },
            );
        }

        let reg_len = r.get_u32("Snap.raw_registers.len")? as usize;
        let mut raw_registers = BTreeMap::new();
        for _ in 0..reg_len {
            let k = r.get_bytes("Snap.reg.k")?;
            let v = r.get_bytes("Snap.reg.v")?;
            raw_registers.insert(k, v);
        }

        let dedup_len = r.get_u32("Snap.cas_dedup.len")? as usize;
        let mut cas_dedup = BTreeMap::new();
        for _ in 0..dedup_len {
            let uid = r.get_u64("Snap.dedup.uid")?;
            let swapped = r.get_bool("Snap.dedup.swapped")?;
            let prev = r.get_opt_bytes("Snap.dedup.prev")?;
            cas_dedup.insert(uid, (swapped, prev));
        }

        Ok(Self {
            keys,
            raw_registers,
            cas_dedup,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zombie_prewrite_blocked_by_check_txn_status_tombstone() {
        let mut store = MvccStore::new();
        // Secondary locked by start_ts=10, Primary ("p") delayed by network chaos.
        // Another transaction calls CheckTxnStatus("p", lock_start_ts=10, caller_current_ts=50):
        let res = store.apply(&StateMachineCmd::CheckTxnStatus {
            primary_key: b"p".to_vec(),
            lock_start_ts: 10,
            caller_current_ts: 50,
        });
        assert!(matches!(
            res,
            ApplyResult::CheckTxn {
                action: TxnStatusAction::MissingPrimaryRolledBack,
                ..
            }
        ));

        // Now delayed Zombie Prewrite(start_ts=10) arrives on Primary "p": MUST BE REJECTED!
        let pw = store.apply(&StateMachineCmd::Prewrite {
            start_ts: 10,
            primary_key: b"p".to_vec(),
            lock_ttl_ts: 100,
            mutations: vec![Mutation {
                op: LockOp::Put,
                key: b"p".to_vec(),
                value: Some(b"999".to_vec()),
            }],
        });
        assert!(matches!(
            pw,
            ApplyResult::Prewrite {
                status: ClientStatus::TxnAborted,
                ..
            }
        ));
    }

    #[test]
    fn test_write_skew_g2_item_blocked_by_read_lock() {
        let mut store = MvccStore::new();
        // Seed x=100, y=100 at start_ts=1, commit_ts=2
        store.apply(&StateMachineCmd::Prewrite {
            start_ts: 1,
            primary_key: b"x".to_vec(),
            lock_ttl_ts: 50,
            mutations: vec![
                Mutation {
                    op: LockOp::Put,
                    key: b"x".to_vec(),
                    value: Some(b"100".to_vec()),
                },
                Mutation {
                    op: LockOp::Put,
                    key: b"y".to_vec(),
                    value: Some(b"100".to_vec()),
                },
            ],
        });
        store.apply(&StateMachineCmd::Commit {
            start_ts: 1,
            commit_ts: 2,
            keys: vec![b"x".to_vec(), b"y".to_vec()],
        });

        // T1 (start_ts=10) reads x, y and writes x=0 -> Prewrites Put(x, 0) + ReadLock(y) and commits at 15
        store.apply(&StateMachineCmd::Prewrite {
            start_ts: 10,
            primary_key: b"x".to_vec(),
            lock_ttl_ts: 50,
            mutations: vec![
                Mutation {
                    op: LockOp::Put,
                    key: b"x".to_vec(),
                    value: Some(b"0".to_vec()),
                },
                Mutation {
                    op: LockOp::ReadLock,
                    key: b"y".to_vec(),
                    value: None,
                },
            ],
        });
        store.apply(&StateMachineCmd::Commit {
            start_ts: 10,
            commit_ts: 15,
            keys: vec![b"x".to_vec(), b"y".to_vec()],
        });

        // T2 (start_ts=11) also read x=100, y=100 and tries to write y=0 -> Prewrites ReadLock(x) + Put(y, 0)
        // MUST fail with WriteConflict because x has Put(commit_ts=15 >= 11) AND y has Lock(commit_ts=15 >= 11)!
        let t2_pw = store.apply(&StateMachineCmd::Prewrite {
            start_ts: 11,
            primary_key: b"x".to_vec(),
            lock_ttl_ts: 50,
            mutations: vec![
                Mutation {
                    op: LockOp::ReadLock,
                    key: b"x".to_vec(),
                    value: None,
                },
                Mutation {
                    op: LockOp::Put,
                    key: b"y".to_vec(),
                    value: Some(b"0".to_vec()),
                },
            ],
        });
        assert!(matches!(
            t2_pw,
            ApplyResult::Prewrite {
                status: ClientStatus::WriteConflict,
                ..
            }
        ));
    }
}
