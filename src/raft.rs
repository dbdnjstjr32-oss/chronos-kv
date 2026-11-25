//! Full Multi-Group Raft Consensus Engine (`chronos_kv::raft`)
//!
//! Features:
//! - Crash-safe persistence (`raft_meta.bin` atomic rename, Append-Only `WalStorage` with Torn-Write recovery,
//!   and `raft_snapshot.bin` atomic rename before WAL compaction).
//! - `PreVote` (prevents partitioned followers from inflating terms) + `CheckQuorum` (forces isolated zombie
//!   leaders in asymmetric partitions to step down).
//! - Mandatory Leader `NoOp` entry on election win before serving any `ReadIndex`.
//! - Lease-free `ReadIndex` with monotonic `read_ctx_id` quorum heartbeat confirmation (immune to `SIGSTOP`
//!   clock freezes and stale heartbeat round confusion).
//! - Multi-chunk `InstallSnapshot` RPC with full CRC32 verification and stale-snapshot guard.
//! - Non-blocking bounded `sync_channel` per peer so `SIGSTOP`ped peers or kernel TCP send-buffer stalls
//!   never block the Raft state machine loop.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::crc32::crc32;
use crate::mvcc::{ApplyResult, MvccStore, ReadOutcome};
use crate::protocol::*;
use crate::storage::{
    load_raft_meta, load_snapshot, save_raft_meta, save_snapshot, PersistedRaftMeta,
    PersistedSnapshot, WalStorage,
};
use crate::wire::{FrameDecoder, WireError, WireFrame};

const HEARTBEAT_INTERVAL_MS: u64 = 45;
const ELECTION_MIN_MS: u64 = 200;
const ELECTION_MAX_MS: u64 = 360;
const CHECK_QUORUM_WINDOW_MS: u64 = 550;
const LEADER_ACTIVE_GUARD_MS: u64 = 160;
const SNAPSHOT_CHUNK_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Follower = 0,
    PreCandidate = 1,
    Candidate = 2,
    Leader = 3,
}

struct PendingProposal {
    term: u64,
    result: Option<ApplyResult>,
}

struct PendingRead {
    term: u64,
    target_read_index: u64,
    acks: BTreeSet<u16>,
    ready: bool,
    failed: bool,
}

struct StagingSnapshot {
    last_included_index: u64,
    last_included_term: u64,
    bytes: Vec<u8>,
}

pub struct PeerConfig {
    pub node_id: u16,
    pub addr: String,
}

struct RaftCore {
    node_id: u16,
    shard_id: u16,
    data_dir: PathBuf,
    peer_ids: Vec<u16>,
    peer_senders: BTreeMap<u16, SyncSender<WireFrame>>,

    role: Role,
    current_term: u64,
    voted_for: Option<u16>,
    leader_id: Option<u16>,

    snapshot_index: u64,
    snapshot_term: u64,
    snapshot_bytes_cache: Vec<u8>,

    log: Vec<LogEntry>,
    wal: WalStorage,
    mvcc: MvccStore,

    commit_index: u64,
    last_applied: u64,

    // Election & CheckQuorum state
    votes_received: BTreeSet<u16>,
    prevotes_received: BTreeSet<u16>,
    last_leader_contact: Instant,
    election_deadline: Instant,
    last_heartbeat_sent: Instant,
    rng_state: u64,

    // Leader replication state
    leader_noop_index: u64,
    next_index: BTreeMap<u16, u64>,
    match_index: BTreeMap<u16, u64>,
    peer_last_ack: BTreeMap<u16, Instant>,
    peer_snapshot_inflight_until: BTreeMap<u16, Instant>,

    // Proposals & Lease-free ReadIndex state
    proposals: BTreeMap<u64, PendingProposal>,
    next_read_ctx_id: u64,
    pending_reads: BTreeMap<u64, PendingRead>,

    // Follower multi-chunk snapshot staging
    staging_snapshot: Option<StagingSnapshot>,

    snapshot_threshold: u64,
    next_wire_req_id: u64,
}

impl RaftCore {
    fn quorum_size(&self) -> usize {
        let total = self.peer_ids.len() + 1;
        (total / 2) + 1
    }

    fn next_rand_u64(&mut self) -> u64 {
        // xorshift64* PRNG seeded with node_id + monotonic/epoch nanos (used ONLY for election jitter)
        let mut x = self.rng_state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng_state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn reset_election_timer(&mut self) {
        let span = ELECTION_MAX_MS - ELECTION_MIN_MS;
        let jitter = self.next_rand_u64() % (span + 1);
        self.election_deadline = Instant::now() + Duration::from_millis(ELECTION_MIN_MS + jitter);
    }

    fn last_log_index(&self) -> u64 {
        self.log.last().map_or(self.snapshot_index, |e| e.index)
    }

    fn last_log_term(&self) -> u64 {
        self.log.last().map_or(self.snapshot_term, |e| e.term)
    }

    fn term_at(&self, index: u64) -> Option<u64> {
        if index == 0 {
            return Some(0);
        }
        if index == self.snapshot_index {
            return Some(self.snapshot_term);
        }
        if index < self.snapshot_index {
            return None;
        }
        let pos = (index - self.snapshot_index - 1) as usize;
        self.log.get(pos).map(|e| e.term)
    }

    fn entry_at(&self, index: u64) -> Option<&LogEntry> {
        if index <= self.snapshot_index {
            return None;
        }
        let pos = (index - self.snapshot_index - 1) as usize;
        self.log.get(pos)
    }

    fn persist_meta(&self) {
        let meta = PersistedRaftMeta {
            current_term: self.current_term,
            voted_for: self.voted_for,
        };
        if let Err(e) = save_raft_meta(&self.data_dir, &meta) {
            eprintln!("[node {}] CRITICAL failed to persist raft_meta: {}", self.node_id, e);
        }
    }

    fn next_req_id(&mut self) -> u64 {
        self.next_wire_req_id = self.next_wire_req_id.wrapping_add(1);
        self.next_wire_req_id
    }

    fn send_to_peer(&self, peer_id: u16, frame: WireFrame) {
        if let Some(tx) = self.peer_senders.get(&peer_id) {
            match tx.try_send(frame) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                    // Non-blocking drop: Raft retries on next heartbeat
                }
            }
        }
    }

    fn step_down(&mut self, new_term: u64, new_leader: Option<u16>) {
        let term_changed = new_term > self.current_term;
        if term_changed {
            self.current_term = new_term;
            self.voted_for = None;
            self.persist_meta();
        }
        self.role = Role::Follower;
        self.leader_id = new_leader;
        self.votes_received.clear();
        self.prevotes_received.clear();
        // Fail any pending reads from older leadership
        for pr in self.pending_reads.values_mut() {
            if !pr.ready {
                pr.failed = true;
            }
        }
    }

    fn is_log_up_to_date(&self, cand_last_idx: u64, cand_last_term: u64) -> bool {
        let my_term = self.last_log_term();
        let my_idx = self.last_log_index();
        cand_last_term > my_term || (cand_last_term == my_term && cand_last_idx >= my_idx)
    }

    fn start_prevote(&mut self) {
        self.role = Role::PreCandidate;
        self.leader_id = None;
        self.prevotes_received.clear();
        self.prevotes_received.insert(self.node_id);
        self.reset_election_timer();

        if self.prevotes_received.len() >= self.quorum_size() {
            self.start_real_election();
            return;
        }

        let prospective_term = self.current_term + 1;
        let last_idx = self.last_log_index();
        let last_term = self.last_log_term();
        let peers = self.peer_ids.clone();

        for pid in peers {
            let req = VoteReq {
                is_prevote: true,
                shard_id: self.shard_id,
                term: prospective_term,
                candidate_id: self.node_id,
                last_log_index: last_idx,
                last_log_term: last_term,
            };
            let rid = self.next_req_id();
            if let Ok(frame) = req.to_frame(rid) {
                self.send_to_peer(pid, frame);
            }
        }
    }

    fn start_real_election(&mut self) {
        self.role = Role::Candidate;
        self.current_term += 1;
        self.voted_for = Some(self.node_id);
        self.leader_id = None;
        self.persist_meta();

        self.votes_received.clear();
        self.votes_received.insert(self.node_id);
        self.reset_election_timer();

        if self.votes_received.len() >= self.quorum_size() {
            self.become_leader();
            return;
        }

        let term = self.current_term;
        let last_idx = self.last_log_index();
        let last_term = self.last_log_term();
        let peers = self.peer_ids.clone();

        for pid in peers {
            let req = VoteReq {
                is_prevote: false,
                shard_id: self.shard_id,
                term,
                candidate_id: self.node_id,
                last_log_index: last_idx,
                last_log_term: last_term,
            };
            let rid = self.next_req_id();
            if let Ok(frame) = req.to_frame(rid) {
                self.send_to_peer(pid, frame);
            }
        }
    }

    fn become_leader(&mut self) {
        self.role = Role::Leader;
        self.leader_id = Some(self.node_id);
        let now = Instant::now();
        let next_idx = self.last_log_index() + 1;

        self.next_index.clear();
        self.match_index.clear();
        self.peer_last_ack.clear();
        self.peer_snapshot_inflight_until.clear();
        for &pid in &self.peer_ids {
            self.next_index.insert(pid, next_idx);
            self.match_index.insert(pid, 0);
            self.peer_last_ack.insert(pid, now);
        }

        // Mandatory Raft Leader No-Op entry in current term before serving ReadIndex!
        let noop_entry = LogEntry {
            term: self.current_term,
            index: next_idx,
            cmd_bytes: StateMachineCmd::NoOp.encode(),
        };
        if let Err(e) = self.wal.append_batch(None, std::slice::from_ref(&noop_entry)) {
            eprintln!("[node {}] WAL append failed on leader noop: {}", self.node_id, e);
        }
        self.log.push(noop_entry);
        self.leader_noop_index = next_idx;

        if self.quorum_size() == 1 {
            self.commit_index = next_idx;
            self.apply_committed();
        } else {
            self.broadcast_append_entries(0);
        }
    }

    fn broadcast_append_entries(&mut self, read_ctx_id: u64) {
        if self.role != Role::Leader {
            return;
        }
        self.last_heartbeat_sent = Instant::now();
        let peers = self.peer_ids.clone();
        for pid in peers {
            self.send_replicate_to_peer(pid, read_ctx_id);
        }
    }

    fn send_replicate_to_peer(&mut self, pid: u16, read_ctx_id: u64) {
        let next_idx = *self.next_index.get(&pid).unwrap_or(&(self.last_log_index() + 1));

        // If follower needs entries already compacted into snapshot, send InstallSnapshot chunks!
        if next_idx <= self.snapshot_index {
            let now = Instant::now();
            if let Some(&until) = self.peer_snapshot_inflight_until.get(&pid) {
                if now < until && read_ctx_id == 0 {
                    return;
                }
            }
            self.peer_snapshot_inflight_until
                .insert(pid, now + Duration::from_millis(350));

            let snap_bytes = self.snapshot_bytes_cache.clone();
            let total_crc = crc32(&snap_bytes);
            let snap_idx = self.snapshot_index;
            let snap_term = self.snapshot_term;
            let term = self.current_term;

            if snap_bytes.is_empty() {
                let req = InstallSnapshotReq {
                    shard_id: self.shard_id,
                    term,
                    leader_id: self.node_id,
                    last_included_index: snap_idx,
                    last_included_term: snap_term,
                    offset: 0,
                    data: Vec::new(),
                    done: true,
                    total_crc32: total_crc,
                };
                let rid = self.next_req_id();
                if let Ok(f) = req.to_frame(rid) {
                    self.send_to_peer(pid, f);
                }
            } else {
                let mut offset = 0usize;
                while offset < snap_bytes.len() {
                    let end = (offset + SNAPSHOT_CHUNK_BYTES).min(snap_bytes.len());
                    let done = end == snap_bytes.len();
                    let req = InstallSnapshotReq {
                        shard_id: self.shard_id,
                        term,
                        leader_id: self.node_id,
                        last_included_index: snap_idx,
                        last_included_term: snap_term,
                        offset: offset as u64,
                        data: snap_bytes[offset..end].to_vec(),
                        done,
                        total_crc32: total_crc,
                    };
                    let rid = self.next_req_id();
                    if let Ok(f) = req.to_frame(rid) {
                        self.send_to_peer(pid, f);
                    }
                    offset = end;
                }
            }
            // If read_ctx_id > 0, also send an empty heartbeat or wait for other peer;
            // still send a heartbeat if needed? No, if next_idx <= snapshot_index, AE would fail prev_log anyway.
            return;
        }

        let prev_log_index = next_idx - 1;
        let prev_log_term = self.term_at(prev_log_index).unwrap_or(self.snapshot_term);

        let mut entries = Vec::new();
        let last_idx = self.last_log_index();
        let max_batch = 64u64;
        let end_idx = last_idx.min(next_idx + max_batch - 1);
        for idx in next_idx..=end_idx {
            if let Some(e) = self.entry_at(idx) {
                entries.push(e.clone());
            }
        }

        let req = AppendEntriesReq {
            shard_id: self.shard_id,
            term: self.current_term,
            leader_id: self.node_id,
            prev_log_index,
            prev_log_term,
            entries,
            leader_commit: self.commit_index,
            read_ctx_id,
        };
        let rid = self.next_req_id();
        if let Ok(frame) = req.to_frame(rid) {
            self.send_to_peer(pid, frame);
        }
    }

    fn advance_leader_commit(&mut self) {
        if self.role != Role::Leader {
            return;
        }
        let last_idx = self.last_log_index();
        let quorum = self.quorum_size();
        for n in ((self.commit_index + 1)..=last_idx).rev() {
            // Raft Figure 8: Only advance commit_index using entries from current_term!
            if self.term_at(n) != Some(self.current_term) {
                continue;
            }
            let mut count = 1usize; // self
            for &m in self.match_index.values() {
                if m >= n {
                    count += 1;
                }
            }
            if count >= quorum {
                self.commit_index = n;
                break;
            }
        }
        self.apply_committed();
    }

    fn apply_committed(&mut self) {
        while self.last_applied < self.commit_index {
            let next_apply = self.last_applied + 1;
            let Some(entry) = self.entry_at(next_apply).cloned() else {
                break;
            };
            let result = match StateMachineCmd::decode(&entry.cmd_bytes) {
                Ok(cmd) => self.mvcc.apply(&cmd),
                Err(e) => {
                    eprintln!("[node {}] failed to decode cmd at {}: {}", self.node_id, next_apply, e);
                    ApplyResult::NoOp
                }
            };
            self.last_applied = next_apply;

            if let Some(prop) = self.proposals.get_mut(&next_apply) {
                if prop.term == entry.term {
                    prop.result = Some(result);
                }
            }
        }

        // Check if any pending ReadIndex requests are now satisfied
        let quorum = self.quorum_size();
        for pr in self.pending_reads.values_mut() {
            if self.role == Role::Leader
                && pr.term == self.current_term
                && pr.acks.len() >= quorum
                && self.last_applied >= pr.target_read_index
            {
                pr.ready = true;
            }
        }

        // Trigger log compaction / snapshot if threshold exceeded
        if self.snapshot_threshold > 0
            && self.last_applied.saturating_sub(self.snapshot_index) >= self.snapshot_threshold
        {
            self.take_local_snapshot();
        }
    }

    fn take_local_snapshot(&mut self) {
        let snap_idx = self.last_applied;
        let Some(snap_term) = self.term_at(snap_idx) else {
            return;
        };
        let state_bytes = self.mvcc.encode_snapshot();
        let snap = PersistedSnapshot {
            last_included_index: snap_idx,
            last_included_term: snap_term,
            state_bytes: state_bytes.clone(),
        };

        // CRITICAL ORDER: 1) Atomically persist snapshot (`staging -> fsync -> rename -> dir fsync`)
        if let Err(e) = save_snapshot(&self.data_dir, &snap) {
            eprintln!("[node {}] save_snapshot failed: {}", self.node_id, e);
            return;
        }

        // 2) Trim in-memory log prefix & atomically compact WAL suffix
        let suffix: Vec<LogEntry> = self
            .log
            .iter()
            .filter(|e| e.index > snap_idx)
            .cloned()
            .collect();
        if let Err(e) = self.wal.compact_with_suffix(&suffix) {
            eprintln!("[node {}] compact_with_suffix failed: {}", self.node_id, e);
        }

        self.snapshot_index = snap_idx;
        self.snapshot_term = snap_term;
        self.snapshot_bytes_cache = state_bytes;
        self.log = suffix;
    }

    fn handle_vote_req(&mut self, req: VoteReq) -> VoteResp {
        if req.is_prevote {
            let active_leader = self.role == Role::Leader
                || (self.leader_id.is_some()
                    && self.last_leader_contact.elapsed()
                        < Duration::from_millis(LEADER_ACTIVE_GUARD_MS));
            let granted = !active_leader
                && req.term > self.current_term
                && self.is_log_up_to_date(req.last_log_index, req.last_log_term);
            return VoteResp {
                is_prevote: true,
                shard_id: self.shard_id,
                term: self.current_term,
                from_id: self.node_id,
                vote_granted: granted,
            };
        }

        if req.term > self.current_term {
            self.step_down(req.term, None);
        }

        let mut granted = false;
        if req.term == self.current_term {
            let can_vote = self.voted_for.is_none() || self.voted_for == Some(req.candidate_id);
            if can_vote && self.is_log_up_to_date(req.last_log_index, req.last_log_term) {
                self.voted_for = Some(req.candidate_id);
                self.persist_meta();
                self.last_leader_contact = Instant::now();
                self.reset_election_timer();
                granted = true;
            }
        }

        VoteResp {
            is_prevote: false,
            shard_id: self.shard_id,
            term: self.current_term,
            from_id: self.node_id,
            vote_granted: granted,
        }
    }

    fn handle_vote_resp(&mut self, resp: VoteResp) {
        if resp.is_prevote {
            if resp.term > self.current_term {
                self.step_down(resp.term, None);
                return;
            }
            if self.role == Role::PreCandidate && resp.vote_granted {
                self.prevotes_received.insert(resp.from_id);
                if self.prevotes_received.len() >= self.quorum_size() {
                    self.start_real_election();
                }
            }
            return;
        }

        if resp.term > self.current_term {
            self.step_down(resp.term, None);
            return;
        }
        if self.role == Role::Candidate && resp.term == self.current_term && resp.vote_granted {
            self.votes_received.insert(resp.from_id);
            if self.votes_received.len() >= self.quorum_size() {
                self.become_leader();
            }
        }
    }

    fn handle_append_entries_req(&mut self, req: AppendEntriesReq) -> AppendEntriesResp {
        if req.term < self.current_term {
            return AppendEntriesResp {
                shard_id: self.shard_id,
                term: self.current_term,
                from_id: self.node_id,
                success: false,
                match_index: 0,
                conflict_index: self.last_log_index() + 1,
                ack_read_ctx_id: 0,
            };
        }

        if req.term > self.current_term || self.role != Role::Follower {
            self.step_down(req.term, Some(req.leader_id));
        } else {
            self.leader_id = Some(req.leader_id);
        }
        self.last_leader_contact = Instant::now();
        self.reset_election_timer();

        // Case A: prev_log_index falls behind our already-compacted snapshot
        if req.prev_log_index < self.snapshot_index {
            let last_in_req = req.prev_log_index + req.entries.len() as u64;
            if last_in_req <= self.snapshot_index {
                if req.leader_commit > self.commit_index {
                    self.commit_index = req.leader_commit.min(self.last_log_index());
                    self.apply_committed();
                }
                return AppendEntriesResp {
                    shard_id: self.shard_id,
                    term: self.current_term,
                    from_id: self.node_id,
                    success: true,
                    match_index: self.snapshot_index,
                    conflict_index: 0,
                    ack_read_ctx_id: req.read_ctx_id,
                };
            }
            // Trim prefix covered by snapshot and re-anchor at snapshot_index
            let skip = (self.snapshot_index - req.prev_log_index) as usize;
            let trimmed = req.entries[skip..].to_vec();
            let synthetic = AppendEntriesReq {
                prev_log_index: self.snapshot_index,
                prev_log_term: self.snapshot_term,
                entries: trimmed,
                ..req
            };
            return self.handle_append_entries_req(synthetic);
        }

        // Case B: Standard prev_log_index >= snapshot_index check
        match self.term_at(req.prev_log_index) {
            None => {
                return AppendEntriesResp {
                    shard_id: self.shard_id,
                    term: self.current_term,
                    from_id: self.node_id,
                    success: false,
                    match_index: 0,
                    conflict_index: self.last_log_index() + 1,
                    ack_read_ctx_id: 0,
                };
            }
            Some(local_term) if local_term != req.prev_log_term => {
                // Fast backtrack to first index of conflicting term
                let mut conflict_idx = req.prev_log_index;
                while conflict_idx > self.snapshot_index + 1 {
                    if self.term_at(conflict_idx - 1) == Some(local_term) {
                        conflict_idx -= 1;
                    } else {
                        break;
                    }
                }
                return AppendEntriesResp {
                    shard_id: self.shard_id,
                    term: self.current_term,
                    from_id: self.node_id,
                    success: false,
                    match_index: 0,
                    conflict_index: conflict_idx,
                    ack_read_ctx_id: 0,
                };
            }
            Some(_) => {}
        }

        // Raft §5.3: Only truncate on an actual conflicting entry, never on a shorter matching prefix!
        let mut truncate_after: Option<u64> = None;
        let mut to_append: Vec<LogEntry> = Vec::new();

        for (i, entry) in req.entries.iter().enumerate() {
            match self.term_at(entry.index) {
                Some(existing_term) if existing_term == entry.term => {
                    continue;
                }
                Some(_conflicting_term) => {
                    let keep_up_to = entry.index - 1;
                    let keep_len = (keep_up_to - self.snapshot_index) as usize;
                    self.log.truncate(keep_len);
                    truncate_after = Some(keep_up_to);
                    to_append.extend_from_slice(&req.entries[i..]);
                    break;
                }
                None => {
                    to_append.extend_from_slice(&req.entries[i..]);
                    break;
                }
            }
        }

        if truncate_after.is_some() || !to_append.is_empty() {
            if let Err(e) = self.wal.append_batch(truncate_after, &to_append) {
                eprintln!("[node {}] follower WAL append failed: {}", self.node_id, e);
            }
            self.log.extend(to_append);
        }

        let match_idx = req.prev_log_index + req.entries.len() as u64;
        if req.leader_commit > self.commit_index {
            let cap = match_idx.max(self.last_log_index());
            self.commit_index = req.leader_commit.min(cap);
            self.apply_committed();
        }

        AppendEntriesResp {
            shard_id: self.shard_id,
            term: self.current_term,
            from_id: self.node_id,
            success: true,
            match_index: match_idx,
            conflict_index: 0,
            ack_read_ctx_id: req.read_ctx_id,
        }
    }

    fn handle_append_entries_resp(&mut self, resp: AppendEntriesResp) {
        if resp.term > self.current_term {
            self.step_down(resp.term, None);
            return;
        }
        if self.role != Role::Leader || resp.term != self.current_term {
            return;
        }

        self.peer_last_ack.insert(resp.from_id, Instant::now());

        // Record Lease-free ReadIndex quorum acknowledgments for matching or earlier read_ctx_id!
        if resp.ack_read_ctx_id > 0 {
            let quorum = self.quorum_size();
            for (&ctx_id, pr) in self.pending_reads.iter_mut() {
                if pr.term == self.current_term && ctx_id <= resp.ack_read_ctx_id {
                    pr.acks.insert(resp.from_id);
                    if pr.acks.len() >= quorum && self.last_applied >= pr.target_read_index {
                        pr.ready = true;
                    }
                }
            }
        }

        if resp.success {
            let cur_match = *self.match_index.get(&resp.from_id).unwrap_or(&0);
            if resp.match_index > cur_match {
                self.match_index.insert(resp.from_id, resp.match_index);
                self.next_index.insert(resp.from_id, resp.match_index + 1);
            }
            self.advance_leader_commit();
            // Pipeline remaining entries if follower still lags behind last_log_index
            if self.next_index.get(&resp.from_id).copied().unwrap_or(0) <= self.last_log_index() {
                self.send_replicate_to_peer(resp.from_id, 0);
            }
        } else {
            let fallback = if resp.conflict_index > 0 {
                resp.conflict_index
            } else {
                self.next_index
                    .get(&resp.from_id)
                    .copied()
                    .unwrap_or(2)
                    .saturating_sub(1)
                    .max(1)
            };
            self.next_index.insert(resp.from_id, fallback);
            self.send_replicate_to_peer(resp.from_id, 0);
        }
    }

    fn handle_install_snapshot_req(&mut self, req: InstallSnapshotReq) -> InstallSnapshotResp {
        if req.term < self.current_term {
            return InstallSnapshotResp {
                shard_id: self.shard_id,
                term: self.current_term,
                from_id: self.node_id,
                last_included_index: req.last_included_index,
                accepted: false,
            };
        }

        if req.term > self.current_term || self.role != Role::Follower {
            self.step_down(req.term, Some(req.leader_id));
        } else {
            self.leader_id = Some(req.leader_id);
        }
        self.last_leader_contact = Instant::now();
        self.reset_election_timer();

        // Stale InstallSnapshot guard (Side Gemini critique #2):
        // Never regress state machine if last_included_index <= commit_index or <= snapshot_index!
        if req.last_included_index <= self.commit_index
            || req.last_included_index <= self.snapshot_index
        {
            return InstallSnapshotResp {
                shard_id: self.shard_id,
                term: self.current_term,
                from_id: self.node_id,
                last_included_index: req.last_included_index,
                accepted: true,
            };
        }

        if req.offset == 0 {
            self.staging_snapshot = Some(StagingSnapshot {
                last_included_index: req.last_included_index,
                last_included_term: req.last_included_term,
                bytes: Vec::new(),
            });
        }

        let Some(staging) = self.staging_snapshot.as_mut() else {
            return InstallSnapshotResp {
                shard_id: self.shard_id,
                term: self.current_term,
                from_id: self.node_id,
                last_included_index: req.last_included_index,
                accepted: false,
            };
        };

        if staging.last_included_index != req.last_included_index
            || staging.last_included_term != req.last_included_term
            || staging.bytes.len() as u64 != req.offset
        {
            self.staging_snapshot = None;
            return InstallSnapshotResp {
                shard_id: self.shard_id,
                term: self.current_term,
                from_id: self.node_id,
                last_included_index: req.last_included_index,
                accepted: false,
            };
        }

        staging.bytes.extend_from_slice(&req.data);

        if !req.done {
            return InstallSnapshotResp {
                shard_id: self.shard_id,
                term: self.current_term,
                from_id: self.node_id,
                last_included_index: req.last_included_index,
                accepted: true,
            };
        }

        let finished = self.staging_snapshot.take().unwrap();
        if crc32(&finished.bytes) != req.total_crc32 {
            eprintln!(
                "[node {}] InstallSnapshot CRC32 mismatch on index {}",
                self.node_id, req.last_included_index
            );
            return InstallSnapshotResp {
                shard_id: self.shard_id,
                term: self.current_term,
                from_id: self.node_id,
                last_included_index: req.last_included_index,
                accepted: false,
            };
        }

        let Ok(new_mvcc) = MvccStore::decode_snapshot(&finished.bytes) else {
            eprintln!(
                "[node {}] InstallSnapshot decode failed on index {}",
                self.node_id, req.last_included_index
            );
            return InstallSnapshotResp {
                shard_id: self.shard_id,
                term: self.current_term,
                from_id: self.node_id,
                last_included_index: req.last_included_index,
                accepted: false,
            };
        };

        // 1) Persist snapshot atomically (`staging -> fsync -> rename -> dir fsync`) BEFORE touching WAL!
        let snap = PersistedSnapshot {
            last_included_index: finished.last_included_index,
            last_included_term: finished.last_included_term,
            state_bytes: finished.bytes.clone(),
        };
        if let Err(e) = save_snapshot(&self.data_dir, &snap) {
            eprintln!("[node {}] save_snapshot on InstallSnapshot failed: {}", self.node_id, e);
            return InstallSnapshotResp {
                shard_id: self.shard_id,
                term: self.current_term,
                from_id: self.node_id,
                last_included_index: req.last_included_index,
                accepted: false,
            };
        }

        // 2) Keep matching log suffix if any, otherwise discard, then rewrite compacted WAL
        let suffix: Vec<LogEntry> = if self.term_at(finished.last_included_index)
            == Some(finished.last_included_term)
        {
            self.log
                .iter()
                .filter(|e| e.index > finished.last_included_index)
                .cloned()
                .collect()
        } else {
            Vec::new()
        };

        let _ = self.wal.compact_with_suffix(&suffix);

        self.snapshot_index = finished.last_included_index;
        self.snapshot_term = finished.last_included_term;
        self.snapshot_bytes_cache = finished.bytes;
        self.log = suffix;
        self.mvcc = new_mvcc;
        self.commit_index = self.commit_index.max(finished.last_included_index);
        self.last_applied = finished.last_included_index;
        self.apply_committed();

        InstallSnapshotResp {
            shard_id: self.shard_id,
            term: self.current_term,
            from_id: self.node_id,
            last_included_index: req.last_included_index,
            accepted: true,
        }
    }

    fn handle_install_snapshot_resp(&mut self, resp: InstallSnapshotResp) {
        if resp.term > self.current_term {
            self.step_down(resp.term, None);
            return;
        }
        if self.role != Role::Leader || resp.term != self.current_term {
            return;
        }
        self.peer_last_ack.insert(resp.from_id, Instant::now());
        self.peer_snapshot_inflight_until.remove(&resp.from_id);

        if resp.accepted {
            let cur_match = *self.match_index.get(&resp.from_id).unwrap_or(&0);
            if resp.last_included_index > cur_match {
                self.match_index
                    .insert(resp.from_id, resp.last_included_index);
                self.next_index
                    .insert(resp.from_id, resp.last_included_index + 1);
            }
            self.advance_leader_commit();
            self.send_replicate_to_peer(resp.from_id, 0);
        }
    }

    fn tick(&mut self) {
        let now = Instant::now();
        match self.role {
            Role::Leader => {
                // CheckQuorum: Step down if isolated from majority in asymmetric partition!
                if self.quorum_size() > 1 {
                    let mut reachable = 1usize; // self
                    for ack_t in self.peer_last_ack.values() {
                        if now.saturating_duration_since(*ack_t)
                            < Duration::from_millis(CHECK_QUORUM_WINDOW_MS)
                        {
                            reachable += 1;
                        }
                    }
                    if reachable < self.quorum_size() {
                        let term = self.current_term;
                        self.step_down(term, None);
                        self.reset_election_timer();
                        return;
                    }
                }
                if now.saturating_duration_since(self.last_heartbeat_sent)
                    >= Duration::from_millis(HEARTBEAT_INTERVAL_MS)
                {
                    self.broadcast_append_entries(0);
                }
            }
            Role::Follower | Role::PreCandidate | Role::Candidate => {
                if now >= self.election_deadline {
                    self.start_prevote();
                }
            }
        }
    }
}

pub struct RaftEngine {
    inner: Mutex<RaftCore>,
    cv: Condvar,
}

impl RaftEngine {
    pub fn open(
        node_id: u16,
        shard_id: u16,
        data_dir: &Path,
        peers: Vec<PeerConfig>,
        snapshot_threshold: u64,
    ) -> Result<Arc<Self>, WireError> {
        let meta = load_raft_meta(data_dir)?;
        let snap_opt = load_snapshot(data_dir)?;

        let (snapshot_index, snapshot_term, snapshot_bytes_cache, mvcc) = match snap_opt {
            Some(s) => {
                let store = MvccStore::decode_snapshot(&s.state_bytes)?;
                (
                    s.last_included_index,
                    s.last_included_term,
                    s.state_bytes,
                    store,
                )
            }
            None => (0, 0, Vec::new(), MvccStore::new()),
        };

        let (wal, recovered_entries, report) = WalStorage::open_and_recover(data_dir, snapshot_index)?;
        if report.torn_bytes_truncated > 0 || report.entries_recovered > 0 {
            eprintln!(
                "[node {} shard {}] Boot recovery: snap_idx={}, wal_entries={}, torn_bytes_truncated={}",
                node_id, shard_id, snapshot_index, report.entries_recovered, report.torn_bytes_truncated
            );
        }

        let seed_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let rng_seed = seed_nanos
            ^ ((node_id as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15))
            ^ ((shard_id as u64) << 32);

        let mut peer_senders = BTreeMap::new();
        let mut peer_channels = Vec::new();
        let mut peer_ids = Vec::new();
        for p in peers {
            if p.node_id == node_id {
                continue;
            }
            let (tx, rx) = mpsc::sync_channel::<WireFrame>(256);
            peer_ids.push(p.node_id);
            peer_senders.insert(p.node_id, tx);
            peer_channels.push((p, rx));
        }

        let now = Instant::now();
        let mut core = RaftCore {
            node_id,
            shard_id,
            data_dir: data_dir.to_path_buf(),
            peer_ids,
            peer_senders,
            role: Role::Follower,
            current_term: meta.current_term,
            voted_for: meta.voted_for,
            leader_id: None,
            snapshot_index,
            snapshot_term,
            snapshot_bytes_cache,
            log: recovered_entries,
            wal,
            mvcc,
            commit_index: snapshot_index,
            last_applied: snapshot_index,
            votes_received: BTreeSet::new(),
            prevotes_received: BTreeSet::new(),
            last_leader_contact: now.checked_sub(Duration::from_secs(10)).unwrap_or(now),
            election_deadline: now + Duration::from_millis(200),
            last_heartbeat_sent: now,
            rng_state: if rng_seed == 0 { 1 } else { rng_seed },
            leader_noop_index: 0,
            next_index: BTreeMap::new(),
            match_index: BTreeMap::new(),
            peer_last_ack: BTreeMap::new(),
            peer_snapshot_inflight_until: BTreeMap::new(),
            proposals: BTreeMap::new(),
            next_read_ctx_id: 1,
            pending_reads: BTreeMap::new(),
            staging_snapshot: None,
            snapshot_threshold,
            next_wire_req_id: 1,
        };
        core.reset_election_timer();

        let engine = Arc::new(Self {
            inner: Mutex::new(core),
            cv: Condvar::new(),
        });

        // Spawn non-blocking per-peer TCP transport workers
        for (peer_cfg, rx) in peer_channels {
            let eng_clone = Arc::clone(&engine);
            thread::spawn(move || {
                peer_transport_loop(eng_clone, peer_cfg, rx);
            });
        }

        // Spawn Raft ticker thread (15ms resolution)
        let eng_tick = Arc::clone(&engine);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(15));
            let mut guard = eng_tick.inner.lock().unwrap();
            guard.tick();
            eng_tick.cv.notify_all();
        });

        Ok(engine)
    }

    pub fn handle_peer_frame(&self, frame: WireFrame) -> Result<Option<WireFrame>, WireError> {
        let mut guard = self.inner.lock().unwrap();
        let out = match frame.msg_type {
            MSG_PRE_VOTE_REQ => {
                let req = VoteReq::decode(true, &frame.payload)?;
                let resp = guard.handle_vote_req(req);
                Some(resp.to_frame(frame.req_id)?)
            }
            MSG_REQUEST_VOTE_REQ => {
                let req = VoteReq::decode(false, &frame.payload)?;
                let resp = guard.handle_vote_req(req);
                Some(resp.to_frame(frame.req_id)?)
            }
            MSG_PRE_VOTE_RESP => {
                let resp = VoteResp::decode(true, &frame.payload)?;
                guard.handle_vote_resp(resp);
                None
            }
            MSG_REQUEST_VOTE_RESP => {
                let resp = VoteResp::decode(false, &frame.payload)?;
                guard.handle_vote_resp(resp);
                None
            }
            MSG_APPEND_ENTRIES_REQ => {
                let req = AppendEntriesReq::decode(&frame.payload)?;
                let resp = guard.handle_append_entries_req(req);
                Some(resp.to_frame(frame.req_id)?)
            }
            MSG_APPEND_ENTRIES_RESP => {
                let resp = AppendEntriesResp::decode(&frame.payload)?;
                guard.handle_append_entries_resp(resp);
                None
            }
            MSG_INSTALL_SNAPSHOT_REQ => {
                let req = InstallSnapshotReq::decode(&frame.payload)?;
                let resp = guard.handle_install_snapshot_req(req);
                Some(resp.to_frame(frame.req_id)?)
            }
            MSG_INSTALL_SNAPSHOT_RESP => {
                let resp = InstallSnapshotResp::decode(&frame.payload)?;
                guard.handle_install_snapshot_resp(resp);
                None
            }
            _ => None,
        };
        self.cv.notify_all();
        Ok(out)
    }

    /// Proposes a deterministic `StateMachineCmd` through Raft consensus and waits until applied.
    pub fn propose(
        &self,
        cmd: StateMachineCmd,
        timeout: Duration,
    ) -> Result<ApplyResult, (ClientStatus, Option<u16>)> {
        let deadline = Instant::now() + timeout;
        let (log_idx, prop_term) = {
            let mut g = self.inner.lock().unwrap();
            if g.role != Role::Leader {
                return Err((ClientStatus::NotLeader, g.leader_id));
            }
            let idx = g.last_log_index() + 1;
            let term = g.current_term;
            let entry = LogEntry {
                term,
                index: idx,
                cmd_bytes: cmd.encode(),
            };
            if g.wal
                .append_batch(None, std::slice::from_ref(&entry))
                .is_err()
            {
                return Err((ClientStatus::TimeoutOrUnavailable, g.leader_id));
            }
            g.log.push(entry);
            g.proposals.insert(
                idx,
                PendingProposal {
                    term,
                    result: None,
                },
            );
            if g.quorum_size() == 1 {
                g.commit_index = idx;
                g.apply_committed();
            } else {
                g.broadcast_append_entries(0);
            }
            (idx, term)
        };

        let mut g = self.inner.lock().unwrap();
        loop {
            if let Some(p) = g.proposals.get(&log_idx) {
                if let Some(res) = p.result.clone() {
                    g.proposals.remove(&log_idx);
                    return Ok(res);
                }
            }
            if g.role != Role::Leader || g.current_term != prop_term {
                let hint = g.leader_id;
                g.proposals.remove(&log_idx);
                return Err((ClientStatus::NotLeader, hint));
            }
            let now = Instant::now();
            if now >= deadline {
                let hint = g.leader_id;
                g.proposals.remove(&log_idx);
                return Err((ClientStatus::TimeoutOrUnavailable, hint));
            }
            let wait_dur = deadline.duration_since(now).min(Duration::from_millis(30));
            let (ng, _) = self.cv.wait_timeout(g, wait_dur).unwrap();
            g = ng;
        }
    }

    /// Lease-free `ReadIndex`:
    /// 1) Waits until current leader's `NoOp` entry in `current_term` is committed.
    /// 2) Records `target_read_index = commit_index` and broadcasts a fresh heartbeat tagged with `read_ctx_id`.
    /// 3) Waits for quorum heartbeat responses in `current_term` with `ack_read_ctx_id >= read_ctx_id`
    ///    AND `last_applied >= target_read_index`, then executes `reader_fn(&mvcc)` atomically under lock!
    pub fn linearizable_read<F, T>(
        &self,
        timeout: Duration,
        reader_fn: F,
    ) -> Result<T, (ClientStatus, Option<u16>)>
    where
        F: FnOnce(&MvccStore) -> T,
    {
        let deadline = Instant::now() + timeout;
        let mut g = self.inner.lock().unwrap();

        // Step 1: Ensure we are Leader AND our current-term NoOp entry is committed!
        while g.role == Role::Leader && g.commit_index < g.leader_noop_index {
            let now = Instant::now();
            if now >= deadline {
                return Err((ClientStatus::TimeoutOrUnavailable, g.leader_id));
            }
            let wait_dur = deadline.duration_since(now).min(Duration::from_millis(25));
            let (ng, _) = self.cv.wait_timeout(g, wait_dur).unwrap();
            g = ng;
        }

        if g.role != Role::Leader {
            return Err((ClientStatus::NotLeader, g.leader_id));
        }

        // Single-node cluster shortcut
        if g.quorum_size() == 1 {
            return Ok(reader_fn(&g.mvcc));
        }

        // Step 2: Issue fresh ReadIndex heartbeat round
        let term = g.current_term;
        let target_read_index = g.commit_index;
        let ctx_id = g.next_read_ctx_id;
        g.next_read_ctx_id += 1;

        let mut acks = BTreeSet::new();
        acks.insert(g.node_id);
        g.pending_reads.insert(
            ctx_id,
            PendingRead {
                term,
                target_read_index,
                acks,
                ready: false,
                failed: false,
            },
        );
        g.broadcast_append_entries(ctx_id);

        // Step 3: Wait for quorum heartbeat acks + state machine catch-up
        loop {
            if let Some(pr) = g.pending_reads.get(&ctx_id) {
                if pr.ready && g.role == Role::Leader && g.current_term == term {
                    g.pending_reads.remove(&ctx_id);
                    return Ok(reader_fn(&g.mvcc));
                }
                if pr.failed {
                    let hint = g.leader_id;
                    g.pending_reads.remove(&ctx_id);
                    return Err((ClientStatus::NotLeader, hint));
                }
            }
            if g.role != Role::Leader || g.current_term != term {
                let hint = g.leader_id;
                g.pending_reads.remove(&ctx_id);
                return Err((ClientStatus::NotLeader, hint));
            }
            let now = Instant::now();
            if now >= deadline {
                let hint = g.leader_id;
                g.pending_reads.remove(&ctx_id);
                return Err((ClientStatus::TimeoutOrUnavailable, hint));
            }
            let wait_dur = deadline.duration_since(now).min(Duration::from_millis(25));
            let (ng, _) = self.cv.wait_timeout(g, wait_dur).unwrap();
            g = ng;
        }
    }

    pub fn read_mvcc(&self, key: &[u8], read_ts: u64, timeout: Duration) -> ClientReadResp {
        match self.linearizable_read(timeout, |mvcc| mvcc.read_at_ts(key, read_ts)) {
            Ok(ReadOutcome::Value(v)) => ClientReadResp {
                status: ClientStatus::Ok,
                value: v,
                lock: None,
                leader_hint: None,
            },
            Ok(ReadOutcome::Locked(lock)) => ClientReadResp {
                status: ClientStatus::KeyLocked,
                value: None,
                lock: Some(lock),
                leader_hint: None,
            },
            Err((status, hint)) => ClientReadResp {
                status,
                value: None,
                lock: None,
                leader_hint: hint,
            },
        }
    }

    pub fn node_status(&self) -> ClientNodeStatusResp {
        let g = self.inner.lock().unwrap();
        let role_code = match g.role {
            Role::Follower => 0,
            Role::PreCandidate | Role::Candidate => 1,
            Role::Leader => 2,
        };
        ClientNodeStatusResp {
            node_id: g.node_id,
            shard_id: g.shard_id,
            role: role_code,
            term: g.current_term,
            commit_index: g.commit_index,
            last_applied: g.last_applied,
            snapshot_index: g.snapshot_index,
            log_len: g.log.len() as u64,
            state_crc32: g.mvcc.state_crc32(),
            leader_hint: g.leader_id,
        }
    }
}

/// Dedicated per-peer TCP client loop:
/// Connects to peer, spawns reader thread for response frames, and writes outbound frames with bounded write timeout.
fn peer_transport_loop(
    engine: Arc<RaftEngine>,
    peer: PeerConfig,
    rx: mpsc::Receiver<WireFrame>,
) {
    let mut stream_opt: Option<TcpStream> = None;

    while let Ok(frame) = rx.recv() {
        if stream_opt.is_none() {
            if let Ok(sock_addr) = peer.addr.parse() {
                if let Ok(s) = TcpStream::connect_timeout(&sock_addr, Duration::from_millis(250)) {
                    let _ = s.set_nodelay(true);
                    let _ = s.set_write_timeout(Some(Duration::from_millis(350)));
                    if let Ok(mut reader_clone) = s.try_clone() {
                        let _ = reader_clone.set_read_timeout(Some(Duration::from_secs(5)));
                        let eng_reader = Arc::clone(&engine);
                        thread::spawn(move || {
                            let mut dec = FrameDecoder::new();
                            loop {
                                match dec.read_frame(&mut reader_clone) {
                                    Ok(Some(resp_frame)) => {
                                        let _ = eng_reader.handle_peer_frame(resp_frame);
                                    }
                                    Ok(None) => break,
                                    Err(WireError::Io(ref e))
                                        if e.kind() == std::io::ErrorKind::WouldBlock
                                            || e.kind() == std::io::ErrorKind::TimedOut =>
                                    {
                                        continue;
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                        stream_opt = Some(s);
                    }
                }
            }
        }

        if let Some(ref mut s) = stream_opt {
            match frame.encode() {
                Ok(raw) => {
                    if s.write_all(&raw).is_err() || s.flush().is_err() {
                        let _ = s.shutdown(std::net::Shutdown::Both);
                        stream_opt = None;
                    }
                }
                Err(_) => {}
            }
        }
    }
}
