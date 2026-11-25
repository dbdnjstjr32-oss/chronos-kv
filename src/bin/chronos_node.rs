//! `chronos-node`: Standalone Raft + Strict-Serializable Percolator MVCC Storage Daemon.

use std::env;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use chronos_kv::mvcc::ApplyResult;
use chronos_kv::protocol::*;
use chronos_kv::raft::{PeerConfig, RaftEngine};
use chronos_kv::wire::{FrameDecoder, WireError, WireFrame};

const RPC_TIMEOUT: Duration = Duration::from_millis(1500);

fn dispatch_frame(engine: &RaftEngine, frame: WireFrame) -> Result<Option<WireFrame>, WireError> {
    match frame.msg_type {
        MSG_PRE_VOTE_REQ
        | MSG_PRE_VOTE_RESP
        | MSG_REQUEST_VOTE_REQ
        | MSG_REQUEST_VOTE_RESP
        | MSG_APPEND_ENTRIES_REQ
        | MSG_APPEND_ENTRIES_RESP
        | MSG_INSTALL_SNAPSHOT_REQ
        | MSG_INSTALL_SNAPSHOT_RESP => engine.handle_peer_frame(frame),

        MSG_CLIENT_READ_REQ => {
            let req = ClientReadReq::decode(&frame.payload)?;
            let resp = engine.read_mvcc(&req.key, req.read_ts, RPC_TIMEOUT);
            Ok(Some(resp.to_frame(frame.req_id)?))
        }

        MSG_CLIENT_PREWRITE_REQ => {
            let req = ClientPrewriteReq::decode(&frame.payload)?;
            let cmd = StateMachineCmd::Prewrite {
                start_ts: req.start_ts,
                primary_key: req.primary_key,
                lock_ttl_ts: req.lock_ttl_ts,
                mutations: req.mutations,
            };
            let resp = match engine.propose(cmd, RPC_TIMEOUT) {
                Ok(ApplyResult::Prewrite {
                    status,
                    reason,
                    blocking_lock,
                }) => ClientPrewriteResp {
                    status,
                    conflict_reason: reason,
                    blocking_lock,
                    leader_hint: None,
                },
                Ok(_) => ClientPrewriteResp {
                    status: ClientStatus::BadRequest,
                    conflict_reason: "unexpected apply result".to_string(),
                    blocking_lock: None,
                    leader_hint: None,
                },
                Err((status, hint)) => ClientPrewriteResp {
                    status,
                    conflict_reason: "raft_not_leader_or_timeout".to_string(),
                    blocking_lock: None,
                    leader_hint: hint,
                },
            };
            Ok(Some(resp.to_frame(frame.req_id)?))
        }

        MSG_CLIENT_COMMIT_REQ => {
            let req = ClientCommitReq::decode(&frame.payload)?;
            let cmd = StateMachineCmd::Commit {
                start_ts: req.start_ts,
                commit_ts: req.commit_ts,
                keys: req.keys,
            };
            let resp = match engine.propose(cmd, RPC_TIMEOUT) {
                Ok(ApplyResult::Commit { status, reason }) => ClientCommitResp {
                    status,
                    conflict_reason: reason,
                    leader_hint: None,
                },
                Ok(_) => ClientCommitResp {
                    status: ClientStatus::BadRequest,
                    conflict_reason: "unexpected apply result".to_string(),
                    leader_hint: None,
                },
                Err((status, hint)) => ClientCommitResp {
                    status,
                    conflict_reason: "raft_not_leader_or_timeout".to_string(),
                    leader_hint: hint,
                },
            };
            Ok(Some(resp.to_frame(frame.req_id)?))
        }

        MSG_CLIENT_ROLLBACK_REQ => {
            let req = ClientRollbackReq::decode(&frame.payload)?;
            let cmd = StateMachineCmd::BatchRollback {
                start_ts: req.start_ts,
                keys: req.keys,
            };
            let resp = match engine.propose(cmd, RPC_TIMEOUT) {
                Ok(ApplyResult::Rollback { status }) => ClientRollbackResp {
                    status,
                    leader_hint: None,
                },
                Ok(_) => ClientRollbackResp {
                    status: ClientStatus::BadRequest,
                    leader_hint: None,
                },
                Err((status, hint)) => ClientRollbackResp {
                    status,
                    leader_hint: hint,
                },
            };
            Ok(Some(resp.to_frame(frame.req_id)?))
        }

        MSG_CLIENT_CHECK_TXN_REQ => {
            let req = ClientCheckTxnReq::decode(&frame.payload)?;
            let cmd = StateMachineCmd::CheckTxnStatus {
                primary_key: req.primary_key,
                lock_start_ts: req.lock_start_ts,
                caller_current_ts: req.caller_current_ts,
            };
            let resp = match engine.propose(cmd, RPC_TIMEOUT) {
                Ok(ApplyResult::CheckTxn { action, commit_ts }) => ClientCheckTxnResp {
                    status: ClientStatus::Ok,
                    action,
                    commit_ts,
                    leader_hint: None,
                },
                Ok(_) => ClientCheckTxnResp {
                    status: ClientStatus::BadRequest,
                    action: TxnStatusAction::AlreadyRolledBack,
                    commit_ts: 0,
                    leader_hint: None,
                },
                Err((status, hint)) => ClientCheckTxnResp {
                    status,
                    action: TxnStatusAction::LockAlive,
                    commit_ts: 0,
                    leader_hint: hint,
                },
            };
            Ok(Some(resp.to_frame(frame.req_id)?))
        }

        MSG_CLIENT_NODE_STATUS_REQ => {
            let resp = engine.node_status();
            Ok(Some(resp.to_frame(frame.req_id)?))
        }

        MSG_CLIENT_RAW_CAS_REQ => {
            let req = ClientRawCasReq::decode(&frame.payload)?;
            let cmd = StateMachineCmd::RawCas {
                key: req.key,
                expected: req.expected,
                desired: req.desired,
                op_uid: req.op_uid,
            };
            let resp = match engine.propose(cmd, RPC_TIMEOUT) {
                Ok(ApplyResult::RawCas {
                    swapped,
                    prev_value,
                }) => ClientRawCasResp {
                    status: ClientStatus::Ok,
                    swapped,
                    prev_value,
                    leader_hint: None,
                },
                Ok(_) => ClientRawCasResp {
                    status: ClientStatus::BadRequest,
                    swapped: false,
                    prev_value: None,
                    leader_hint: None,
                },
                Err((status, hint)) => ClientRawCasResp {
                    status,
                    swapped: false,
                    prev_value: None,
                    leader_hint: hint,
                },
            };
            Ok(Some(resp.to_frame(frame.req_id)?))
        }

        MSG_CLIENT_RAW_GET_REQ => {
            let req = ClientRawGetReq::decode(&frame.payload)?;
            let resp = match engine.linearizable_read(RPC_TIMEOUT, |mvcc| mvcc.raw_get(&req.key)) {
                Ok(val) => ClientRawGetResp {
                    status: ClientStatus::Ok,
                    value: val,
                    leader_hint: None,
                },
                Err((status, hint)) => ClientRawGetResp {
                    status,
                    value: None,
                    leader_hint: hint,
                },
            };
            Ok(Some(resp.to_frame(frame.req_id)?))
        }

        _ => Ok(None),
    }
}

fn handle_conn(mut stream: TcpStream, engine: Arc<RaftEngine>) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let mut dec = FrameDecoder::new();

    loop {
        match dec.read_frame(&mut stream) {
            Ok(Some(frame)) => match dispatch_frame(&engine, frame) {
                Ok(Some(resp_frame)) => {
                    if resp_frame.write_to(&mut stream).is_err() {
                        break;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("[chronos-node] frame dispatch error (closing socket): {}", e);
                    break;
                }
            },
            Ok(None) => break,
            Err(WireError::Io(ref e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                eprintln!("[chronos-node] wire decode/CRC error (closing socket): {}", e);
                break;
            }
        }
    }
}

fn parse_peers(spec: &str) -> Vec<PeerConfig> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if let Some((id_str, addr_str)) = p.split_once('=') {
            if let Ok(node_id) = id_str.trim().parse::<u16>() {
                out.push(PeerConfig {
                    node_id,
                    addr: addr_str.trim().to_string(),
                });
            }
        }
    }
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut node_id: u16 = 0;
    let mut shard_id: u16 = 0;
    let mut listen_addr = String::from("127.0.0.1:18000");
    let mut data_dir = String::from("/tmp/chronos_node_0");
    let mut peers_spec = String::new();
    let mut snapshot_threshold: u64 = 80;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--node-id" if i + 1 < args.len() => {
                node_id = args[i + 1].parse().expect("invalid --node-id");
                i += 2;
            }
            "--shard-id" if i + 1 < args.len() => {
                shard_id = args[i + 1].parse().expect("invalid --shard-id");
                i += 2;
            }
            "--listen" if i + 1 < args.len() => {
                listen_addr = args[i + 1].clone();
                i += 2;
            }
            "--data-dir" if i + 1 < args.len() => {
                data_dir = args[i + 1].clone();
                i += 2;
            }
            "--peers" if i + 1 < args.len() => {
                peers_spec = args[i + 1].clone();
                i += 2;
            }
            "--snapshot-threshold" if i + 1 < args.len() => {
                snapshot_threshold = args[i + 1].parse().unwrap_or(80);
                i += 2;
            }
            _ => i += 1,
        }
    }

    let peers = parse_peers(&peers_spec);
    let listener = TcpListener::bind(&listen_addr)
        .unwrap_or_else(|e| panic!("failed to bind chronos-node on {}: {}", listen_addr, e));

    let engine = RaftEngine::open(
        node_id,
        shard_id,
        Path::new(&data_dir),
        peers,
        snapshot_threshold,
    )
    .expect("failed to open RaftEngine");

    eprintln!(
        "[chronos-node] Ready node_id={} shard_id={} listen={} snap_thresh={}",
        node_id, shard_id, listen_addr, snapshot_threshold
    );

    for incoming in listener.incoming() {
        if let Ok(stream) = incoming {
            let eng = Arc::clone(&engine);
            thread::spawn(move || handle_conn(stream, eng));
        }
    }
}
