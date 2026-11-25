//! Wire Message Definitions (`msg_type` tags and binary codecs) for TSO, Raft, Percolator MVCC,
//! Linearizable Raw Registers, and Chaos Proxy Control.

use crate::wire::{ByteReader, ByteWriter, WireError, WireFrame};

// --- Message Type Tags ---
pub const MSG_TSO_ALLOC_REQ: u8 = 0x01;
pub const MSG_TSO_ALLOC_RESP: u8 = 0x02;

pub const MSG_PRE_VOTE_REQ: u8 = 0x10;
pub const MSG_PRE_VOTE_RESP: u8 = 0x11;
pub const MSG_REQUEST_VOTE_REQ: u8 = 0x12;
pub const MSG_REQUEST_VOTE_RESP: u8 = 0x13;
pub const MSG_APPEND_ENTRIES_REQ: u8 = 0x14;
pub const MSG_APPEND_ENTRIES_RESP: u8 = 0x15;
pub const MSG_INSTALL_SNAPSHOT_REQ: u8 = 0x16;
pub const MSG_INSTALL_SNAPSHOT_RESP: u8 = 0x17;

pub const MSG_CLIENT_READ_REQ: u8 = 0x20;
pub const MSG_CLIENT_READ_RESP: u8 = 0x21;
pub const MSG_CLIENT_PREWRITE_REQ: u8 = 0x22;
pub const MSG_CLIENT_PREWRITE_RESP: u8 = 0x23;
pub const MSG_CLIENT_COMMIT_REQ: u8 = 0x24;
pub const MSG_CLIENT_COMMIT_RESP: u8 = 0x25;
pub const MSG_CLIENT_ROLLBACK_REQ: u8 = 0x26;
pub const MSG_CLIENT_ROLLBACK_RESP: u8 = 0x27;
pub const MSG_CLIENT_CHECK_TXN_REQ: u8 = 0x28;
pub const MSG_CLIENT_CHECK_TXN_RESP: u8 = 0x29;
pub const MSG_CLIENT_NODE_STATUS_REQ: u8 = 0x2A;
pub const MSG_CLIENT_NODE_STATUS_RESP: u8 = 0x2B;
pub const MSG_CLIENT_RAW_CAS_REQ: u8 = 0x2C;
pub const MSG_CLIENT_RAW_CAS_RESP: u8 = 0x2D;
pub const MSG_CLIENT_RAW_GET_REQ: u8 = 0x2E;
pub const MSG_CLIENT_RAW_GET_RESP: u8 = 0x2F;

pub const MSG_CHAOS_SET_POLICY_REQ: u8 = 0x40;
pub const MSG_CHAOS_SET_POLICY_RESP: u8 = 0x41;

// --- TSO ---
#[derive(Debug, Clone)]
pub struct TsoAllocReq {
    pub count: u32,
}

impl TsoAllocReq {
    pub fn to_frame(&self, req_id: u64) -> Result<WireFrame, WireError> {
        let mut w = ByteWriter::with_capacity(4);
        w.put_u32(self.count);
        Ok(WireFrame::new(MSG_TSO_ALLOC_REQ, req_id, w.into_vec()))
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        Ok(Self {
            count: r.get_u32("TsoAllocReq.count")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct TsoAllocResp {
    pub base_ts: u64,
    pub count: u32,
}

impl TsoAllocResp {
    pub fn to_frame(&self, req_id: u64) -> Result<WireFrame, WireError> {
        let mut w = ByteWriter::with_capacity(12);
        w.put_u64(self.base_ts);
        w.put_u32(self.count);
        Ok(WireFrame::new(MSG_TSO_ALLOC_RESP, req_id, w.into_vec()))
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        Ok(Self {
            base_ts: r.get_u64("TsoAllocResp.base_ts")?,
            count: r.get_u32("TsoAllocResp.count")?,
        })
    }
}

// --- Percolator Mutations & State Machine Commands ---
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockOp {
    Put = 1,
    Delete = 2,
    ReadLock = 3,
}

impl LockOp {
    pub fn from_u8(v: u8) -> Result<Self, WireError> {
        match v {
            1 => Ok(LockOp::Put),
            2 => Ok(LockOp::Delete),
            3 => Ok(LockOp::ReadLock),
            tag => Err(WireError::InvalidEnumTag {
                context: "LockOp",
                tag,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mutation {
    pub op: LockOp,
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
}

impl Mutation {
    pub fn encode_into(&self, w: &mut ByteWriter) {
        w.put_u8(self.op as u8);
        w.put_bytes(&self.key);
        w.put_opt_bytes(&self.value);
    }

    pub fn decode_from(r: &mut ByteReader<'_>) -> Result<Self, WireError> {
        let op = LockOp::from_u8(r.get_u8("Mutation.op")?)?;
        let key = r.get_bytes("Mutation.key")?;
        let value = r.get_opt_bytes("Mutation.value")?;
        Ok(Self { op, key, value })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockInfo {
    pub key: Vec<u8>,
    pub primary_key: Vec<u8>,
    pub start_ts: u64,
    pub ttl_ts: u64,
    pub op: LockOp,
}

impl LockInfo {
    pub fn encode_into(&self, w: &mut ByteWriter) {
        w.put_bytes(&self.key);
        w.put_bytes(&self.primary_key);
        w.put_u64(self.start_ts);
        w.put_u64(self.ttl_ts);
        w.put_u8(self.op as u8);
    }

    pub fn decode_from(r: &mut ByteReader<'_>) -> Result<Self, WireError> {
        Ok(Self {
            key: r.get_bytes("LockInfo.key")?,
            primary_key: r.get_bytes("LockInfo.primary_key")?,
            start_ts: r.get_u64("LockInfo.start_ts")?,
            ttl_ts: r.get_u64("LockInfo.ttl_ts")?,
            op: LockOp::from_u8(r.get_u8("LockInfo.op")?)?,
        })
    }
}

/// Deterministic command replicated in the Raft log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateMachineCmd {
    NoOp,
    Prewrite {
        start_ts: u64,
        primary_key: Vec<u8>,
        lock_ttl_ts: u64,
        mutations: Vec<Mutation>,
    },
    Commit {
        start_ts: u64,
        commit_ts: u64,
        keys: Vec<Vec<u8>>,
    },
    BatchRollback {
        start_ts: u64,
        keys: Vec<Vec<u8>>,
    },
    CheckTxnStatus {
        primary_key: Vec<u8>,
        lock_start_ts: u64,
        caller_current_ts: u64,
    },
    RawCas {
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        desired: Vec<u8>,
        op_uid: u64,
    },
}

impl StateMachineCmd {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ByteWriter::new();
        match self {
            StateMachineCmd::NoOp => w.put_u8(0),
            StateMachineCmd::Prewrite {
                start_ts,
                primary_key,
                lock_ttl_ts,
                mutations,
            } => {
                w.put_u8(1);
                w.put_u64(*start_ts);
                w.put_bytes(primary_key);
                w.put_u64(*lock_ttl_ts);
                w.put_u32(mutations.len() as u32);
                for m in mutations {
                    m.encode_into(&mut w);
                }
            }
            StateMachineCmd::Commit {
                start_ts,
                commit_ts,
                keys,
            } => {
                w.put_u8(2);
                w.put_u64(*start_ts);
                w.put_u64(*commit_ts);
                w.put_u32(keys.len() as u32);
                for k in keys {
                    w.put_bytes(k);
                }
            }
            StateMachineCmd::BatchRollback { start_ts, keys } => {
                w.put_u8(3);
                w.put_u64(*start_ts);
                w.put_u32(keys.len() as u32);
                for k in keys {
                    w.put_bytes(k);
                }
            }
            StateMachineCmd::CheckTxnStatus {
                primary_key,
                lock_start_ts,
                caller_current_ts,
            } => {
                w.put_u8(4);
                w.put_bytes(primary_key);
                w.put_u64(*lock_start_ts);
                w.put_u64(*caller_current_ts);
            }
            StateMachineCmd::RawCas {
                key,
                expected,
                desired,
                op_uid,
            } => {
                w.put_u8(5);
                w.put_bytes(key);
                w.put_opt_bytes(expected);
                w.put_bytes(desired);
                w.put_u64(*op_uid);
            }
        }
        w.into_vec()
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        match r.get_u8("StateMachineCmd.tag")? {
            0 => Ok(StateMachineCmd::NoOp),
            1 => {
                let start_ts = r.get_u64("Prewrite.start_ts")?;
                let primary_key = r.get_bytes("Prewrite.primary_key")?;
                let lock_ttl_ts = r.get_u64("Prewrite.lock_ttl_ts")?;
                let n = r.get_u32("Prewrite.mutations.len")? as usize;
                let mut mutations = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    mutations.push(Mutation::decode_from(&mut r)?);
                }
                Ok(StateMachineCmd::Prewrite {
                    start_ts,
                    primary_key,
                    lock_ttl_ts,
                    mutations,
                })
            }
            2 => {
                let start_ts = r.get_u64("Commit.start_ts")?;
                let commit_ts = r.get_u64("Commit.commit_ts")?;
                let n = r.get_u32("Commit.keys.len")? as usize;
                let mut keys = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    keys.push(r.get_bytes("Commit.key")?);
                }
                Ok(StateMachineCmd::Commit {
                    start_ts,
                    commit_ts,
                    keys,
                })
            }
            3 => {
                let start_ts = r.get_u64("Rollback.start_ts")?;
                let n = r.get_u32("Rollback.keys.len")? as usize;
                let mut keys = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    keys.push(r.get_bytes("Rollback.key")?);
                }
                Ok(StateMachineCmd::BatchRollback { start_ts, keys })
            }
            4 => Ok(StateMachineCmd::CheckTxnStatus {
                primary_key: r.get_bytes("CheckTxn.primary_key")?,
                lock_start_ts: r.get_u64("CheckTxn.lock_start_ts")?,
                caller_current_ts: r.get_u64("CheckTxn.caller_current_ts")?,
            }),
            5 => Ok(StateMachineCmd::RawCas {
                key: r.get_bytes("RawCas.key")?,
                expected: r.get_opt_bytes("RawCas.expected")?,
                desired: r.get_bytes("RawCas.desired")?,
                op_uid: r.get_u64("RawCas.op_uid")?,
            }),
            tag => Err(WireError::InvalidEnumTag {
                context: "StateMachineCmd",
                tag,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub term: u64,
    pub index: u64,
    pub cmd_bytes: Vec<u8>,
}

impl LogEntry {
    pub fn encode_into(&self, w: &mut ByteWriter) {
        w.put_u64(self.term);
        w.put_u64(self.index);
        w.put_bytes(&self.cmd_bytes);
    }

    pub fn decode_from(r: &mut ByteReader<'_>) -> Result<Self, WireError> {
        Ok(Self {
            term: r.get_u64("LogEntry.term")?,
            index: r.get_u64("LogEntry.index")?,
            cmd_bytes: r.get_bytes("LogEntry.cmd_bytes")?,
        })
    }
}

// --- Raft Peer Messages ---
#[derive(Debug, Clone)]
pub struct VoteReq {
    pub is_prevote: bool,
    pub shard_id: u16,
    pub term: u64,
    pub candidate_id: u16,
    pub last_log_index: u64,
    pub last_log_term: u64,
}

impl VoteReq {
    pub fn to_frame(&self, req_id: u64) -> Result<WireFrame, WireError> {
        let mut w = ByteWriter::with_capacity(28);
        w.put_u16(self.shard_id);
        w.put_u64(self.term);
        w.put_u16(self.candidate_id);
        w.put_u64(self.last_log_index);
        w.put_u64(self.last_log_term);
        let msg_type = if self.is_prevote {
            MSG_PRE_VOTE_REQ
        } else {
            MSG_REQUEST_VOTE_REQ
        };
        Ok(WireFrame::new(msg_type, req_id, w.into_vec()))
    }

    pub fn decode(is_prevote: bool, buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        Ok(Self {
            is_prevote,
            shard_id: r.get_u16("VoteReq.shard_id")?,
            term: r.get_u64("VoteReq.term")?,
            candidate_id: r.get_u16("VoteReq.candidate_id")?,
            last_log_index: r.get_u64("VoteReq.last_log_index")?,
            last_log_term: r.get_u64("VoteReq.last_log_term")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct VoteResp {
    pub is_prevote: bool,
    pub shard_id: u16,
    pub term: u64,
    pub from_id: u16,
    pub vote_granted: bool,
}

impl VoteResp {
    pub fn to_frame(&self, req_id: u64) -> Result<WireFrame, WireError> {
        let mut w = ByteWriter::with_capacity(16);
        w.put_u16(self.shard_id);
        w.put_u64(self.term);
        w.put_u16(self.from_id);
        w.put_bool(self.vote_granted);
        let msg_type = if self.is_prevote {
            MSG_PRE_VOTE_RESP
        } else {
            MSG_REQUEST_VOTE_RESP
        };
        Ok(WireFrame::new(msg_type, req_id, w.into_vec()))
    }

    pub fn decode(is_prevote: bool, buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        Ok(Self {
            is_prevote,
            shard_id: r.get_u16("VoteResp.shard_id")?,
            term: r.get_u64("VoteResp.term")?,
            from_id: r.get_u16("VoteResp.from_id")?,
            vote_granted: r.get_bool("VoteResp.vote_granted")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AppendEntriesReq {
    pub shard_id: u16,
    pub term: u64,
    pub leader_id: u16,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
    pub entries: Vec<LogEntry>,
    pub leader_commit: u64,
    pub read_ctx_id: u64,
}

impl AppendEntriesReq {
    pub fn to_frame(&self, req_id: u64) -> Result<WireFrame, WireError> {
        let mut w = ByteWriter::with_capacity(64 + self.entries.len() * 32);
        w.put_u16(self.shard_id);
        w.put_u64(self.term);
        w.put_u16(self.leader_id);
        w.put_u64(self.prev_log_index);
        w.put_u64(self.prev_log_term);
        w.put_u32(self.entries.len() as u32);
        for e in &self.entries {
            e.encode_into(&mut w);
        }
        w.put_u64(self.leader_commit);
        w.put_u64(self.read_ctx_id);
        Ok(WireFrame::new(MSG_APPEND_ENTRIES_REQ, req_id, w.into_vec()))
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        let shard_id = r.get_u16("AE.shard_id")?;
        let term = r.get_u64("AE.term")?;
        let leader_id = r.get_u16("AE.leader_id")?;
        let prev_log_index = r.get_u64("AE.prev_log_index")?;
        let prev_log_term = r.get_u64("AE.prev_log_term")?;
        let n = r.get_u32("AE.entries.len")? as usize;
        let mut entries = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            entries.push(LogEntry::decode_from(&mut r)?);
        }
        let leader_commit = r.get_u64("AE.leader_commit")?;
        let read_ctx_id = r.get_u64("AE.read_ctx_id")?;
        Ok(Self {
            shard_id,
            term,
            leader_id,
            prev_log_index,
            prev_log_term,
            entries,
            leader_commit,
            read_ctx_id,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AppendEntriesResp {
    pub shard_id: u16,
    pub term: u64,
    pub from_id: u16,
    pub success: bool,
    pub match_index: u64,
    pub conflict_index: u64,
    pub ack_read_ctx_id: u64,
}

impl AppendEntriesResp {
    pub fn to_frame(&self, req_id: u64) -> Result<WireFrame, WireError> {
        let mut w = ByteWriter::with_capacity(40);
        w.put_u16(self.shard_id);
        w.put_u64(self.term);
        w.put_u16(self.from_id);
        w.put_bool(self.success);
        w.put_u64(self.match_index);
        w.put_u64(self.conflict_index);
        w.put_u64(self.ack_read_ctx_id);
        Ok(WireFrame::new(
            MSG_APPEND_ENTRIES_RESP,
            req_id,
            w.into_vec(),
        ))
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        Ok(Self {
            shard_id: r.get_u16("AEResp.shard_id")?,
            term: r.get_u64("AEResp.term")?,
            from_id: r.get_u16("AEResp.from_id")?,
            success: r.get_bool("AEResp.success")?,
            match_index: r.get_u64("AEResp.match_index")?,
            conflict_index: r.get_u64("AEResp.conflict_index")?,
            ack_read_ctx_id: r.get_u64("AEResp.ack_read_ctx_id")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct InstallSnapshotReq {
    pub shard_id: u16,
    pub term: u64,
    pub leader_id: u16,
    pub last_included_index: u64,
    pub last_included_term: u64,
    pub offset: u64,
    pub data: Vec<u8>,
    pub done: bool,
    pub total_crc32: u32,
}

impl InstallSnapshotReq {
    pub fn to_frame(&self, req_id: u64) -> Result<WireFrame, WireError> {
        let mut w = ByteWriter::with_capacity(48 + self.data.len());
        w.put_u16(self.shard_id);
        w.put_u64(self.term);
        w.put_u16(self.leader_id);
        w.put_u64(self.last_included_index);
        w.put_u64(self.last_included_term);
        w.put_u64(self.offset);
        w.put_bytes(&self.data);
        w.put_bool(self.done);
        w.put_u32(self.total_crc32);
        Ok(WireFrame::new(
            MSG_INSTALL_SNAPSHOT_REQ,
            req_id,
            w.into_vec(),
        ))
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        Ok(Self {
            shard_id: r.get_u16("IS.shard_id")?,
            term: r.get_u64("IS.term")?,
            leader_id: r.get_u16("IS.leader_id")?,
            last_included_index: r.get_u64("IS.last_included_index")?,
            last_included_term: r.get_u64("IS.last_included_term")?,
            offset: r.get_u64("IS.offset")?,
            data: r.get_bytes("IS.data")?,
            done: r.get_bool("IS.done")?,
            total_crc32: r.get_u32("IS.total_crc32")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct InstallSnapshotResp {
    pub shard_id: u16,
    pub term: u64,
    pub from_id: u16,
    pub last_included_index: u64,
    pub accepted: bool,
}

impl InstallSnapshotResp {
    pub fn to_frame(&self, req_id: u64) -> Result<WireFrame, WireError> {
        let mut w = ByteWriter::with_capacity(24);
        w.put_u16(self.shard_id);
        w.put_u64(self.term);
        w.put_u16(self.from_id);
        w.put_u64(self.last_included_index);
        w.put_bool(self.accepted);
        Ok(WireFrame::new(
            MSG_INSTALL_SNAPSHOT_RESP,
            req_id,
            w.into_vec(),
        ))
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        Ok(Self {
            shard_id: r.get_u16("ISResp.shard_id")?,
            term: r.get_u64("ISResp.term")?,
            from_id: r.get_u16("ISResp.from_id")?,
            last_included_index: r.get_u64("ISResp.last_included_index")?,
            accepted: r.get_bool("ISResp.accepted")?,
        })
    }
}

// --- Client RPC Status & Payloads ---
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientStatus {
    Ok = 0,
    NotLeader = 1,
    KeyLocked = 2,
    WriteConflict = 3,
    TxnAborted = 4,
    TimeoutOrUnavailable = 5,
    BadRequest = 6,
}

impl ClientStatus {
    pub fn from_u8(v: u8) -> Result<Self, WireError> {
        match v {
            0 => Ok(ClientStatus::Ok),
            1 => Ok(ClientStatus::NotLeader),
            2 => Ok(ClientStatus::KeyLocked),
            3 => Ok(ClientStatus::WriteConflict),
            4 => Ok(ClientStatus::TxnAborted),
            5 => Ok(ClientStatus::TimeoutOrUnavailable),
            6 => Ok(ClientStatus::BadRequest),
            tag => Err(WireError::InvalidEnumTag {
                context: "ClientStatus",
                tag,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxnStatusAction {
    AlreadyCommitted = 1,
    AlreadyRolledBack = 2,
    TtlExpiredRolledBack = 3,
    MissingPrimaryRolledBack = 4,
    LockAlive = 5,
}

impl TxnStatusAction {
    pub fn from_u8(v: u8) -> Result<Self, WireError> {
        match v {
            1 => Ok(TxnStatusAction::AlreadyCommitted),
            2 => Ok(TxnStatusAction::AlreadyRolledBack),
            3 => Ok(TxnStatusAction::TtlExpiredRolledBack),
            4 => Ok(TxnStatusAction::MissingPrimaryRolledBack),
            5 => Ok(TxnStatusAction::LockAlive),
            tag => Err(WireError::InvalidEnumTag {
                context: "TxnStatusAction",
                tag,
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientReadReq {
    pub key: Vec<u8>,
    pub read_ts: u64,
}

impl ClientReadReq {
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        Ok(Self {
            key: r.get_bytes("ClientReadReq.key")?,
            read_ts: r.get_u64("ClientReadReq.read_ts")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ClientReadResp {
    pub status: ClientStatus,
    pub value: Option<Vec<u8>>,
    pub lock: Option<LockInfo>,
    pub leader_hint: Option<u16>,
}

impl ClientReadResp {
    pub fn to_frame(&self, req_id: u64) -> Result<WireFrame, WireError> {
        let mut w = ByteWriter::new();
        w.put_u8(self.status as u8);
        w.put_opt_bytes(&self.value);
        match &self.lock {
            Some(l) => {
                w.put_bool(true);
                l.encode_into(&mut w);
            }
            None => w.put_bool(false),
        }
        w.put_opt_u16(self.leader_hint);
        Ok(WireFrame::new(MSG_CLIENT_READ_RESP, req_id, w.into_vec()))
    }
}

#[derive(Debug, Clone)]
pub struct ClientPrewriteReq {
    pub start_ts: u64,
    pub primary_key: Vec<u8>,
    pub lock_ttl_ts: u64,
    pub mutations: Vec<Mutation>,
}

impl ClientPrewriteReq {
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        let start_ts = r.get_u64("PrewriteReq.start_ts")?;
        let primary_key = r.get_bytes("PrewriteReq.primary_key")?;
        let lock_ttl_ts = r.get_u64("PrewriteReq.lock_ttl_ts")?;
        let n = r.get_u32("PrewriteReq.mutations.len")? as usize;
        let mut mutations = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            mutations.push(Mutation::decode_from(&mut r)?);
        }
        Ok(Self {
            start_ts,
            primary_key,
            lock_ttl_ts,
            mutations,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ClientPrewriteResp {
    pub status: ClientStatus,
    pub conflict_reason: String,
    pub blocking_lock: Option<LockInfo>,
    pub leader_hint: Option<u16>,
}

impl ClientPrewriteResp {
    pub fn to_frame(&self, req_id: u64) -> Result<WireFrame, WireError> {
        let mut w = ByteWriter::new();
        w.put_u8(self.status as u8);
        w.put_str(&self.conflict_reason);
        match &self.blocking_lock {
            Some(l) => {
                w.put_bool(true);
                l.encode_into(&mut w);
            }
            None => w.put_bool(false),
        }
        w.put_opt_u16(self.leader_hint);
        Ok(WireFrame::new(
            MSG_CLIENT_PREWRITE_RESP,
            req_id,
            w.into_vec(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ClientCommitReq {
    pub start_ts: u64,
    pub commit_ts: u64,
    pub keys: Vec<Vec<u8>>,
}

impl ClientCommitReq {
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        let start_ts = r.get_u64("CommitReq.start_ts")?;
        let commit_ts = r.get_u64("CommitReq.commit_ts")?;
        let n = r.get_u32("CommitReq.keys.len")? as usize;
        let mut keys = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            keys.push(r.get_bytes("CommitReq.key")?);
        }
        Ok(Self {
            start_ts,
            commit_ts,
            keys,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ClientCommitResp {
    pub status: ClientStatus,
    pub conflict_reason: String,
    pub leader_hint: Option<u16>,
}

impl ClientCommitResp {
    pub fn to_frame(&self, req_id: u64) -> Result<WireFrame, WireError> {
        let mut w = ByteWriter::new();
        w.put_u8(self.status as u8);
        w.put_str(&self.conflict_reason);
        w.put_opt_u16(self.leader_hint);
        Ok(WireFrame::new(MSG_CLIENT_COMMIT_RESP, req_id, w.into_vec()))
    }
}

#[derive(Debug, Clone)]
pub struct ClientRollbackReq {
    pub start_ts: u64,
    pub keys: Vec<Vec<u8>>,
}

impl ClientRollbackReq {
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        let start_ts = r.get_u64("RollbackReq.start_ts")?;
        let n = r.get_u32("RollbackReq.keys.len")? as usize;
        let mut keys = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            keys.push(r.get_bytes("RollbackReq.key")?);
        }
        Ok(Self { start_ts, keys })
    }
}

#[derive(Debug, Clone)]
pub struct ClientRollbackResp {
    pub status: ClientStatus,
    pub leader_hint: Option<u16>,
}

impl ClientRollbackResp {
    pub fn to_frame(&self, req_id: u64) -> Result<WireFrame, WireError> {
        let mut w = ByteWriter::new();
        w.put_u8(self.status as u8);
        w.put_opt_u16(self.leader_hint);
        Ok(WireFrame::new(
            MSG_CLIENT_ROLLBACK_RESP,
            req_id,
            w.into_vec(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ClientCheckTxnReq {
    pub primary_key: Vec<u8>,
    pub lock_start_ts: u64,
    pub caller_current_ts: u64,
}

impl ClientCheckTxnReq {
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        Ok(Self {
            primary_key: r.get_bytes("CheckTxnReq.primary_key")?,
            lock_start_ts: r.get_u64("CheckTxnReq.lock_start_ts")?,
            caller_current_ts: r.get_u64("CheckTxnReq.caller_current_ts")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ClientCheckTxnResp {
    pub status: ClientStatus,
    pub action: TxnStatusAction,
    pub commit_ts: u64,
    pub leader_hint: Option<u16>,
}

impl ClientCheckTxnResp {
    pub fn to_frame(&self, req_id: u64) -> Result<WireFrame, WireError> {
        let mut w = ByteWriter::new();
        w.put_u8(self.status as u8);
        w.put_u8(self.action as u8);
        w.put_u64(self.commit_ts);
        w.put_opt_u16(self.leader_hint);
        Ok(WireFrame::new(
            MSG_CLIENT_CHECK_TXN_RESP,
            req_id,
            w.into_vec(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ClientNodeStatusResp {
    pub node_id: u16,
    pub shard_id: u16,
    pub role: u8, // 0=Follower, 1=Candidate, 2=Leader
    pub term: u64,
    pub commit_index: u64,
    pub last_applied: u64,
    pub snapshot_index: u64,
    pub log_len: u64,
    pub state_crc32: u32,
    pub leader_hint: Option<u16>,
}

impl ClientNodeStatusResp {
    pub fn to_frame(&self, req_id: u64) -> Result<WireFrame, WireError> {
        let mut w = ByteWriter::with_capacity(56);
        w.put_u16(self.node_id);
        w.put_u16(self.shard_id);
        w.put_u8(self.role);
        w.put_u64(self.term);
        w.put_u64(self.commit_index);
        w.put_u64(self.last_applied);
        w.put_u64(self.snapshot_index);
        w.put_u64(self.log_len);
        w.put_u32(self.state_crc32);
        w.put_opt_u16(self.leader_hint);
        Ok(WireFrame::new(
            MSG_CLIENT_NODE_STATUS_RESP,
            req_id,
            w.into_vec(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ClientRawCasReq {
    pub key: Vec<u8>,
    pub expected: Option<Vec<u8>>,
    pub desired: Vec<u8>,
    pub op_uid: u64,
}

impl ClientRawCasReq {
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        Ok(Self {
            key: r.get_bytes("RawCasReq.key")?,
            expected: r.get_opt_bytes("RawCasReq.expected")?,
            desired: r.get_bytes("RawCasReq.desired")?,
            op_uid: r.get_u64("RawCasReq.op_uid")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ClientRawCasResp {
    pub status: ClientStatus,
    pub swapped: bool,
    pub prev_value: Option<Vec<u8>>,
    pub leader_hint: Option<u16>,
}

impl ClientRawCasResp {
    pub fn to_frame(&self, req_id: u64) -> Result<WireFrame, WireError> {
        let mut w = ByteWriter::new();
        w.put_u8(self.status as u8);
        w.put_bool(self.swapped);
        w.put_opt_bytes(&self.prev_value);
        w.put_opt_u16(self.leader_hint);
        Ok(WireFrame::new(
            MSG_CLIENT_RAW_CAS_RESP,
            req_id,
            w.into_vec(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ClientRawGetReq {
    pub key: Vec<u8>,
}

impl ClientRawGetReq {
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        Ok(Self {
            key: r.get_bytes("RawGetReq.key")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ClientRawGetResp {
    pub status: ClientStatus,
    pub value: Option<Vec<u8>>,
    pub leader_hint: Option<u16>,
}

impl ClientRawGetResp {
    pub fn to_frame(&self, req_id: u64) -> Result<WireFrame, WireError> {
        let mut w = ByteWriter::new();
        w.put_u8(self.status as u8);
        w.put_opt_bytes(&self.value);
        w.put_opt_u16(self.leader_hint);
        Ok(WireFrame::new(
            MSG_CLIENT_RAW_GET_RESP,
            req_id,
            w.into_vec(),
        ))
    }
}

// --- L4 Chaos Proxy Dynamic Link Policy ---
#[derive(Debug, Clone)]
pub struct ChaosSetPolicyReq {
    /// Named directional link (e.g. "s0_n0->s0_n1", "s0_n1->s0_n0", "*" for all)
    pub link_name: String,
    pub drop_all: bool,
    pub delay_ms: u32,
    pub max_chunk_bytes: u32, // 0 = normal, 1..=3 = micro-fragmentation torture!
    pub reset_existing: bool,
}

impl ChaosSetPolicyReq {
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = ByteReader::new(buf);
        Ok(Self {
            link_name: r.get_str("ChaosPolicy.link_name")?,
            drop_all: r.get_bool("ChaosPolicy.drop_all")?,
            delay_ms: r.get_u32("ChaosPolicy.delay_ms")?,
            max_chunk_bytes: r.get_u32("ChaosPolicy.max_chunk_bytes")?,
            reset_existing: r.get_bool("ChaosPolicy.reset_existing")?,
        })
    }
}
