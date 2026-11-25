#!/usr/bin/env python3
"""
`chaos_campaign.py`: End-to-End Multi-Process Black-Box Chaos Campaign for ChronosKV.

Spawns 8 independent native Linux ELF OS processes:
  - 1 × `chronos-tso` (Monotonic Timestamp Oracle)
  - 1 × `chronos-chaos-proxy` (External L4 Raw-Byte TCP Fault Injector)
  - 6 × `chronos-node` (Shard 0: nodes 0,1,2; Shard 1: nodes 10,11,12)

Runs concurrent client threads executing:
  - Cross-shard Percolator 2PC Bank Transfers (`acct_00..acct_04` <-> `m_acct_05..m_acct_09`)
  - Cross-shard Adversarial Write-Skew (`G2-item`) Dual-Reserve Withdrawals & Replenishments (`res_a`, `m_res_b`)
  - Multi-shard Strict-Serializable Read-Only Global Audits (`ro_audit`)
  - Concurrent Single-Key Linearizable `RawCas` / `RawGet` Register Contention (`reg_0`, `m_reg_1`)

While injecting 5 live external chaos stages:
  Stage 1: L4 1~2 Byte TCP Micro-Fragmentation across all peer & client links (`max_chunk_bytes=2`)
  Stage 2: Asymmetric One-Way Network Partition against Shard 0 Leader (`CheckQuorum` + `PreVote` + `ReadIndex`)
  Stage 3: Zombie Leader `SIGSTOP` Freeze (`1.3s`) + `SIGCONT` Thaw on Shard 1 Leader
  Stage 4: Hard `SIGKILL` Assassination on `chronos-tso` + Shard 0 & Shard 1 Nodes + External Disk WAL
           Torn-Write Tail Corruption (`b"CWAL\\xde\\xad\\xbe"`) + Process Restart & Recovery
  Stage 5: Lagging Node Catch-Up via Multi-Chunk `InstallSnapshot` + Full Cluster Healing +
           Replica `state_crc32` Byte-Identical Convergence Check & Independent Oracle Verification!
"""

from __future__ import annotations

import json
import os
import random
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from oracle_verifier import verify_history_file
from wire_client import (
    BinaryCodec,
    ChronosCoordinator,
    MSG_CLIENT_PREWRITE_REQ,
    MSG_CLIENT_PREWRITE_RESP,
    MSG_CLIENT_READ_REQ,
    MSG_CLIENT_READ_RESP,
    NodeStatus,
    OP_PUT,
    STATUS_OK,
    STATUS_TXN_ABORTED,
    query_node_status,
    rpc_call,
    set_chaos_policy,
)

ROOT = Path(__file__).resolve().parent.parent
BIN_DIR = ROOT / "bin"

ACCOUNTS = [
    b"acct_00",
    b"acct_01",
    b"acct_02",
    b"acct_03",
    b"acct_04",
    b"m_acct_05",
    b"m_acct_06",
    b"m_acct_07",
    b"m_acct_08",
    b"m_acct_09",
]
RESERVE_A = b"res_a"      # Shard 0
RESERVE_B = b"m_res_b"    # Shard 1
RAW_KEYS = [b"reg_alpha", b"m_reg_beta"]


def decode_tagged(raw: Optional[bytes]) -> Tuple[str, str, int]:
    if raw is None:
        return ("INIT", "TX_GENESIS", 0)
    s = raw.decode("utf-8")
    v_uid, tx_id, val_s = s.split(":", 2)
    return v_uid, tx_id, int(val_s)


def encode_tagged(ver_uid: str, tx_id: str, val: int) -> bytes:
    return f"{ver_uid}:{tx_id}:{val}".encode("utf-8")


class ManagedDaemon:
    def __init__(self, name: str, cmd: List[str], log_path: Path):
        self.name = name
        self.cmd = cmd
        self.log_path = log_path
        self.proc: Optional[subprocess.Popen] = None
        self._log_fh = None

    def start(self) -> int:
        self._log_fh = open(self.log_path, "ab")
        self.proc = subprocess.Popen(
            self.cmd,
            stdout=self._log_fh,
            stderr=subprocess.STDOUT,
        )
        return self.proc.pid

    def pid(self) -> int:
        assert self.proc is not None
        return self.proc.pid

    def sigstop(self) -> None:
        if self.proc and self.proc.poll() is None:
            os.kill(self.proc.pid, signal.SIGSTOP)

    def sigcont(self) -> None:
        if self.proc and self.proc.poll() is None:
            os.kill(self.proc.pid, signal.SIGCONT)

    def sigkill_and_wait(self) -> None:
        if self.proc and self.proc.poll() is None:
            os.kill(self.proc.pid, signal.SIGKILL)
            self.proc.wait(timeout=5)
        if self._log_fh:
            self._log_fh.close()
            self._log_fh = None

    def terminate_clean(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                os.kill(self.proc.pid, signal.SIGCONT)
            except Exception:
                pass
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.kill(self.proc.pid, signal.SIGKILL)
                self.proc.wait(timeout=3)
        if self._log_fh:
            self._log_fh.close()
            self._log_fh = None


def find_free_port_block(base_candidates=(24000, 26000, 28000, 31000)) -> int:
    import socket

    for base in base_candidates:
        ok = True
        for offset in range(45):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(("127.0.0.1", base + offset)) == 0:
                    ok = False
                    break
        if ok:
            return base
    raise RuntimeError("Could not find contiguous free loopback port block")


def run_campaign() -> int:
    t_campaign_start = time.monotonic()
    run_id = f"run_{int(time.time())}_{os.getpid()}"
    # Native Linux ext4 data dir for authentic POSIX fsync + ftruncate semantics
    ext4_run_dir = Path(f"/tmp/chronos_ext4_{run_id}")
    ext4_run_dir.mkdir(parents=True, exist_ok=True)

    # Persistent workspace artifacts dir for logs, JSONL history, and final report
    ws_run_dir = ROOT / "runs" / run_id
    ws_run_dir.mkdir(parents=True, exist_ok=True)

    history_path = ws_run_dir / "client_history.jsonl"
    chaos_events_path = ws_run_dir / "chaos_events.jsonl"
    summary_path = ws_run_dir / "campaign_summary.json"

    base_port = find_free_port_block()
    tso_port = base_port + 0
    chaos_ctrl_port = base_port + 1

    # Shard 0 nodes: 0, 1, 2; Shard 1 nodes: 10, 11, 12
    shards_nodes = {
        0: [0, 1, 2],
        1: [10, 11, 12],
    }
    real_node_ports: Dict[int, int] = {}
    client_proxy_ports: Dict[int, int] = {}
    all_nids = [0, 1, 2, 10, 11, 12]
    for idx, nid in enumerate(all_nids):
        real_node_ports[nid] = base_port + 2 + idx        # +2..+7
        client_proxy_ports[nid] = base_port + 8 + idx     # +8..+13

    # Peer-to-peer proxy ports: for each shard, 6 ordered pairs (src -> dst)
    peer_proxy_ports: Dict[Tuple[int, int], int] = {}
    port_cursor = base_port + 14
    proxy_routes: List[str] = []

    # Client -> Node proxy routes
    for nid in all_nids:
        fwd = f"cli->n{nid}"
        rev = f"n{nid}->cli"
        l_addr = f"127.0.0.1:{client_proxy_ports[nid]}"
        t_addr = f"127.0.0.1:{real_node_ports[nid]}"
        proxy_routes.extend(["--route", f"{fwd},{rev},{l_addr},{t_addr}"])

    # Peer -> Peer proxy routes (directional L4 control!)
    for sid, nids in shards_nodes.items():
        for src in nids:
            for dst in nids:
                if src == dst:
                    continue
                pport = port_cursor
                port_cursor += 1
                peer_proxy_ports[(src, dst)] = pport
                fwd = f"n{src}->n{dst}"
                rev = f"n{dst}->n{src}"
                l_addr = f"127.0.0.1:{pport}"
                t_addr = f"127.0.0.1:{real_node_ports[dst]}"
                proxy_routes.extend(["--route", f"{fwd},{rev},{l_addr},{t_addr}"])

    daemons: List[ManagedDaemon] = []
    node_daemons: Dict[int, ManagedDaemon] = {}
    node_data_dirs: Dict[int, Path] = {}

    def record_chaos_event(event: str, details: dict) -> None:
        entry = {"ts_mono_s": round(time.monotonic() - t_campaign_start, 4), "event": event, **details}
        print(f"[CHAOS] {entry['ts_mono_s']:6.2f}s | {event} | {details}", flush=True)
        with open(chaos_events_path, "a", encoding="utf-8") as cf:
            cf.write(json.dumps(entry) + "\n")

    try:
        # 1. Start L4 Chaos Proxy
        proxy_cmd = [
            str(BIN_DIR / "chronos-chaos-proxy"),
            "--control-listen",
            f"127.0.0.1:{chaos_ctrl_port}",
            *proxy_routes,
        ]
        proxy_daemon = ManagedDaemon("chaos-proxy", proxy_cmd, ws_run_dir / "chaos_proxy.log")
        proxy_pid = proxy_daemon.start()
        daemons.append(proxy_daemon)

        # 2. Start Monotonic TSO (`--batch-window 250` so disk atomic rename triggers frequently!)
        tso_data_dir = ext4_run_dir / "tso"
        tso_cmd = [
            str(BIN_DIR / "chronos-tso"),
            "--listen",
            f"127.0.0.1:{tso_port}",
            "--data-dir",
            str(tso_data_dir),
            "--batch-window",
            "250",
        ]
        tso_daemon = ManagedDaemon("tso", tso_cmd, ws_run_dir / "tso.log")
        tso_pid = tso_daemon.start()
        daemons.append(tso_daemon)

        # 3. Start 6 independent `chronos-node` OS processes (`--snapshot-threshold 65`)
        for sid, nids in shards_nodes.items():
            for nid in nids:
                ndir = ext4_run_dir / f"node_{nid}"
                node_data_dirs[nid] = ndir
                peers_arg = ",".join(
                    f"{other}=127.0.0.1:{peer_proxy_ports[(nid, other)]}"
                    for other in nids
                    if other != nid
                )
                ncmd = [
                    str(BIN_DIR / "chronos-node"),
                    "--node-id",
                    str(nid),
                    "--shard-id",
                    str(sid),
                    "--listen",
                    f"127.0.0.1:{real_node_ports[nid]}",
                    "--data-dir",
                    str(ndir),
                    "--peers",
                    peers_arg,
                    "--snapshot-threshold",
                    "65",
                ]
                nd = ManagedDaemon(f"node_{nid}", ncmd, ws_run_dir / f"node_{nid}.log")
                nd.start()
                daemons.append(nd)
                node_daemons[nid] = nd

        record_chaos_event(
            "CLUSTER_BOOTED",
            {
                "proxy_pid": proxy_pid,
                "tso_pid": tso_pid,
                "node_pids": {nid: node_daemons[nid].pid() for nid in all_nids},
            },
        )

        # Wait for both shards to elect initial leaders
        time.sleep(0.8)
        shard_client_endpoints = {
            sid: {nid: ("127.0.0.1", client_proxy_ports[nid]) for nid in nids}
            for sid, nids in shards_nodes.items()
        }
        coord = ChronosCoordinator(
            tso_addr=("127.0.0.1", tso_port),
            shard_endpoints=shard_client_endpoints,
            lock_ttl_ts=120,
        )

        # History Recorder (Thread-safe JSONL writer)
        hist_lock = threading.Lock()
        seq_counter = 0

        def next_uid() -> int:
            nonlocal seq_counter
            with hist_lock:
                seq_counter += 1
                return seq_counter

        def append_history(obj: dict) -> None:
            with hist_lock:
                with open(history_path, "a", encoding="utf-8") as hf:
                    hf.write(json.dumps(obj) + "\n")

        # Genesis Initialization Transaction: Seed 10 accounts = 1000 each (Total = 10,000) + 2 Reserves = 100 each
        inv0 = time.perf_counter_ns()
        init_tx_id = "TX_INIT_0"
        init_reads_rec: List[ dict ] = []
        init_writes_rec: List[ dict ] = []

        def seed_fn(tx):
            init_reads_rec.clear()
            init_writes_rec.clear()
            for acct in ACCOUNTS:
                cur = tx.get(acct)
                init_reads_rec.append({"key": acct.decode(), "val": cur.decode() if cur else None})
                nv = encode_tagged(f"v_{next_uid()}", init_tx_id, 1000)
                tx.put(acct, nv)
                init_writes_rec.append(
                    {"key": acct.decode(), "prev_val": cur.decode() if cur else None, "new_val": nv.decode()}
                )
            for rkey in (RESERVE_A, RESERVE_B):
                cur = tx.get(rkey)
                init_reads_rec.append({"key": rkey.decode(), "val": cur.decode() if cur else None})
                nv = encode_tagged(f"v_{next_uid()}", init_tx_id, 100)
                tx.put(rkey, nv)
                init_writes_rec.append(
                    {"key": rkey.decode(), "prev_val": cur.decode() if cur else None, "new_val": nv.decode()}
                )

        coord.execute_rw_txn(seed_fn)
        resp0 = time.perf_counter_ns()
        append_history(
            {
                "record_type": "txn",
                "tx_id": init_tx_id,
                "kind": "init",
                "committed": True,
                "inv_ns": inv0,
                "resp_ns": resp0,
                "reads": init_reads_rec,
                "writes": init_writes_rec,
            }
        )
        record_chaos_event("GENESIS_SEED_COMMITTED", {"accounts": 10, "total_balance": 10000, "reserves": 200})

        # Launch Concurrent Adversarial Workload Threads
        stop_workers = threading.Event()
        worker_stats = {
            "transfers_ok": 0,
            "reserve_withdraw_ok": 0,
            "reserve_replenish_ok": 0,
            "ro_audits_ok": 0,
            "raw_cas_ok": 0,
            "raw_get_ok": 0,
            "orphan_secondary_locks_injected": 0,
            "zombie_primary_prewrites_rejected": 0,
            "tx_aborts_or_timeouts": 0,
        }
        stats_lock = threading.Lock()

        def bank_transfer_worker(worker_id: int) -> None:
            rng = random.Random(1000 + worker_id)
            w_coord = ChronosCoordinator(("127.0.0.1", tso_port), shard_client_endpoints, lock_ttl_ts=120)
            while not stop_workers.is_set():
                # 75% cross-shard transfer, 25% intra-shard transfer
                if rng.random() < 0.75:
                    src = rng.choice(ACCOUNTS[:5])
                    dst = rng.choice(ACCOUNTS[5:])
                    if rng.random() < 0.5:
                        src, dst = dst, src
                else:
                    src, dst = rng.sample(ACCOUNTS, 2)

                amount = rng.randint(10, 90)
                tx_id = f"TX_TR_{worker_id}_{next_uid()}"
                attempt_reads: List[dict] = []
                attempt_writes: List[dict] = []

                def do_transfer(tx):
                    attempt_reads.clear()
                    attempt_writes.clear()
                    # Read in deterministic or arbitrary order (coordinator sorts locks!)
                    raw_s = tx.get(src)
                    raw_d = tx.get(dst)
                    attempt_reads.append({"key": src.decode(), "val": raw_s.decode() if raw_s else None})
                    attempt_reads.append({"key": dst.decode(), "val": raw_d.decode() if raw_d else None})
                    _, _, bal_s = decode_tagged(raw_s)
                    _, _, bal_d = decode_tagged(raw_d)
                    actual_amt = min(amount, bal_s)
                    if actual_amt > 0:
                        nv_s = encode_tagged(f"v_{next_uid()}", tx_id, bal_s - actual_amt)
                        nv_d = encode_tagged(f"v_{next_uid()}", tx_id, bal_d + actual_amt)
                        tx.put(src, nv_s)
                        tx.put(dst, nv_d)
                        attempt_writes.append(
                            {"key": src.decode(), "prev_val": raw_s.decode() if raw_s else None, "new_val": nv_s.decode()}
                        )
                        attempt_writes.append(
                            {"key": dst.decode(), "prev_val": raw_d.decode() if raw_d else None, "new_val": nv_d.decode()}
                        )

                inv_ns = time.perf_counter_ns()
                try:
                    w_coord.execute_rw_txn(do_transfer, max_retries=25)
                    resp_ns = time.perf_counter_ns()
                    append_history(
                        {
                            "record_type": "txn",
                            "tx_id": tx_id,
                            "kind": "transfer",
                            "committed": True,
                            "inv_ns": inv_ns,
                            "resp_ns": resp_ns,
                            "reads": list(attempt_reads),
                            "writes": list(attempt_writes),
                        }
                    )
                    with stats_lock:
                        worker_stats["transfers_ok"] += 1
                except Exception:
                    with stats_lock:
                        worker_stats["tx_aborts_or_timeouts"] += 1
                time.sleep(0.005)

        def write_skew_adversary_worker(worker_id: int) -> None:
            """
            Classic G2-item Write Skew Torture:
            Two workers simultaneously read (`res_a` on Shard 0, `m_res_b` on Shard 1).
            Worker 0 tries to withdraw 100 from `res_a` if `res_a + m_res_b >= 200`;
            Worker 1 tries to withdraw 100 from `m_res_b` if `res_a + m_res_b >= 200`!
            When sum drops to 100, resets both back to 100 (`sum = 200`).
            """
            w_coord = ChronosCoordinator(("127.0.0.1", tso_port), shard_client_endpoints, lock_ttl_ts=120)
            target_key = RESERVE_A if (worker_id % 2 == 0) else RESERVE_B

            while not stop_workers.is_set():
                tx_id = f"TX_WS_{worker_id}_{next_uid()}"
                attempt_reads: List[dict] = []
                attempt_writes: List[dict] = []
                kind_holder = ["reserve_withdraw"]

                def do_skew_op(tx):
                    attempt_reads.clear()
                    attempt_writes.clear()
                    ra = tx.get(RESERVE_A)
                    rb = tx.get(RESERVE_B)
                    attempt_reads.append({"key": RESERVE_A.decode(), "val": ra.decode() if ra else None})
                    attempt_reads.append({"key": RESERVE_B.decode(), "val": rb.decode() if rb else None})
                    _, _, va = decode_tagged(ra)
                    _, _, vb = decode_tagged(rb)
                    if va + vb >= 200:
                        kind_holder[0] = "reserve_withdraw"
                        if target_key == RESERVE_A and va >= 100:
                            nv = encode_tagged(f"v_{next_uid()}", tx_id, va - 100)
                            tx.put(RESERVE_A, nv)
                            attempt_writes.append(
                                {"key": RESERVE_A.decode(), "prev_val": ra.decode(), "new_val": nv.decode()}
                            )
                        elif target_key == RESERVE_B and vb >= 100:
                            nv = encode_tagged(f"v_{next_uid()}", tx_id, vb - 100)
                            tx.put(RESERVE_B, nv)
                            attempt_writes.append(
                                {"key": RESERVE_B.decode(), "prev_val": rb.decode(), "new_val": nv.decode()}
                            )
                    else:
                        kind_holder[0] = "reserve_replenish"
                        if va < 100:
                            nva = encode_tagged(f"v_{next_uid()}", tx_id, 100)
                            tx.put(RESERVE_A, nva)
                            attempt_writes.append(
                                {"key": RESERVE_A.decode(), "prev_val": ra.decode(), "new_val": nva.decode()}
                            )
                        if vb < 100:
                            nvb = encode_tagged(f"v_{next_uid()}", tx_id, 100)
                            tx.put(RESERVE_B, nvb)
                            attempt_writes.append(
                                {"key": RESERVE_B.decode(), "prev_val": rb.decode(), "new_val": nvb.decode()}
                            )

                inv_ns = time.perf_counter_ns()
                try:
                    w_coord.execute_rw_txn(do_skew_op, max_retries=25)
                    resp_ns = time.perf_counter_ns()
                    append_history(
                        {
                            "record_type": "txn",
                            "tx_id": tx_id,
                            "kind": kind_holder[0],
                            "committed": True,
                            "inv_ns": inv_ns,
                            "resp_ns": resp_ns,
                            "reads": list(attempt_reads),
                            "writes": list(attempt_writes),
                        }
                    )
                    with stats_lock:
                        if kind_holder[0] == "reserve_withdraw":
                            worker_stats["reserve_withdraw_ok"] += 1
                        else:
                            worker_stats["reserve_replenish_ok"] += 1
                except Exception:
                    with stats_lock:
                        worker_stats["tx_aborts_or_timeouts"] += 1
                time.sleep(0.01)

        def ro_global_audit_worker() -> None:
            w_coord = ChronosCoordinator(("127.0.0.1", tso_port), shard_client_endpoints, lock_ttl_ts=120)
            audit_keys = ACCOUNTS + [RESERVE_A, RESERVE_B]
            while not stop_workers.is_set():
                tx_id = f"TX_RO_{next_uid()}"
                inv_ns = time.perf_counter_ns()
                try:
                    _rts, snap = w_coord.read_only_snapshot(audit_keys)
                    resp_ns = time.perf_counter_ns()
                    reads_rec = [
                        {"key": k.decode(), "val": snap[k].decode() if snap[k] is not None else None}
                        for k in audit_keys
                    ]
                    append_history(
                        {
                            "record_type": "txn",
                            "tx_id": tx_id,
                            "kind": "ro_audit",
                            "committed": True,
                            "inv_ns": inv_ns,
                            "resp_ns": resp_ns,
                            "reads": reads_rec,
                            "writes": [],
                        }
                    )
                    with stats_lock:
                        worker_stats["ro_audits_ok"] += 1
                except Exception:
                    with stats_lock:
                        worker_stats["tx_aborts_or_timeouts"] += 1
                time.sleep(0.03)

        def linearizable_register_worker(worker_id: int) -> None:
            rng = random.Random(5000 + worker_id)
            w_coord = ChronosCoordinator(("127.0.0.1", tso_port), shard_client_endpoints)
            last_seen: Dict[bytes, Optional[bytes]] = {k: None for k in RAW_KEYS}
            while not stop_workers.is_set():
                rkey = RAW_KEYS[worker_id % len(RAW_KEYS)]
                op_id = next_uid()
                if rng.random() < 0.45:
                    inv_ns = time.perf_counter_ns()
                    try:
                        val = w_coord.raw_get(rkey)
                        resp_ns = time.perf_counter_ns()
                        last_seen[rkey] = val
                        append_history(
                            {
                                "record_type": "raw_reg",
                                "key": rkey.decode(),
                                "op_id": op_id,
                                "kind": "get",
                                "inv_ns": inv_ns,
                                "resp_ns": resp_ns,
                                "observed": val.decode() if val is not None else None,
                            }
                        )
                        with stats_lock:
                            worker_stats["raw_get_ok"] += 1
                    except Exception:
                        pass
                else:
                    exp = last_seen[rkey]
                    des = f"val_{worker_id}_{op_id}".encode("utf-8")
                    inv_ns = time.perf_counter_ns()
                    try:
                        swapped, prev = w_coord.raw_cas(rkey, exp, des, op_uid=op_id)
                        resp_ns = time.perf_counter_ns()
                        last_seen[rkey] = des if swapped else prev
                        append_history(
                            {
                                "record_type": "raw_reg",
                                "key": rkey.decode(),
                                "op_id": op_id,
                                "kind": "cas",
                                "inv_ns": inv_ns,
                                "resp_ns": resp_ns,
                                "expected": exp.decode() if exp is not None else None,
                                "desired": des.decode(),
                                "swapped": swapped,
                                "observed": prev.decode() if prev is not None else None,
                            }
                        )
                        with stats_lock:
                            worker_stats["raw_cas_ok"] += 1
                    except Exception:
                        pass
                time.sleep(0.018)

        def zombie_and_orphan_2pc_attacker() -> None:
            """
            External adversarial client speaking raw `CKV1` wire frames over TCP:
            1) Locks Secondary `m_acct_08` (`primary_key=acct_03`) with bogus value `999999` and short TTL=20,
               withholding Primary `Prewrite` to simulate extreme asymmetric network stall / crashed 2PC client.
            2) Waits 220ms while normal transfers/audits collide with the orphan lock on `m_acct_08` and invoke
               `CheckTxnStatus(acct_03)` (writing permanent Rollback tombstone on Primary `acct_03`).
            3) Fires delayed Zombie `Prewrite(start_ts)` at Primary `acct_03` and verifies `STATUS_TXN_ABORTED`!
            """
            import struct as _st

            adv_coord = ChronosCoordinator(("127.0.0.1", tso_port), shard_client_endpoints, lock_ttl_ts=20)
            while not stop_workers.is_set():
                try:
                    z_sts = adv_coord.alloc_ts(1)
                    prim_k = b"acct_03"
                    sec_k = b"m_acct_08"
                    bogus_val = f"v_zombie_{next_uid()}:TX_ZOMBIE_{z_sts}:999999".encode("utf-8")

                    # Step 1: Send Prewrite ONLY to Secondary shard (Shard 1)
                    sec_pw = bytearray(_st.pack("<Q", z_sts))
                    sec_pw.extend(BinaryCodec.pack_bytes(prim_k))
                    sec_pw.extend(_st.pack("<QI", 20, 1))
                    sec_pw.append(OP_PUT)
                    sec_pw.extend(BinaryCodec.pack_bytes(sec_k))
                    sec_pw.extend(BinaryCodec.pack_opt_bytes(bogus_val))

                    def _pw_parse(rtype: int, body: bytes):
                        if rtype != MSG_CLIENT_PREWRITE_RESP:
                            raise RuntimeError("bad resp")
                        pos = 0
                        st_code, pos = BinaryCodec.unpack_u8(body, pos)
                        reason, pos = BinaryCodec.unpack_str(body, pos)
                        has_lk, pos = BinaryCodec.unpack_bool(body, pos)
                        if has_lk:
                            # skip LockInfo fields to reach leader_hint
                            _, pos = BinaryCodec.unpack_bytes(body, pos)
                            _, pos = BinaryCodec.unpack_bytes(body, pos)
                            _, pos = BinaryCodec.unpack_u64(body, pos)
                            _, pos = BinaryCodec.unpack_u64(body, pos)
                            _, pos = BinaryCodec.unpack_u8(body, pos)
                        hint, pos = BinaryCodec.unpack_opt_u16(body, pos)
                        return st_code, hint, reason

                    sec_st, _ = adv_coord._shard_rpc(1, MSG_CLIENT_PREWRITE_REQ, bytes(sec_pw), _pw_parse, max_wait=2.0)
                    if sec_st == STATUS_OK:
                        with stats_lock:
                            worker_stats["orphan_secondary_locks_injected"] += 1
                        # Record aborted TX_ZOMBIE in history so G1a checker also verifies nobody EVER reads bogus_val!
                        append_history(
                            {
                                "record_type": "txn",
                                "tx_id": f"TX_ZOMBIE_{z_sts}",
                                "kind": "zombie_attack",
                                "committed": False,
                                "inv_ns": time.perf_counter_ns(),
                                "resp_ns": time.perf_counter_ns(),
                                "reads": [],
                                "writes": [{"key": sec_k.decode(), "prev_val": None, "new_val": bogus_val.decode()}],
                            }
                        )
                        # Wait so concurrent workers hit `m_acct_08` and trigger CheckTxnStatus(acct_03)!
                        time.sleep(0.25)
                        # Also explicitly ensure CheckTxnStatus ran if no random worker hit `m_acct_08` in that 250ms window
                        adv_coord.check_txn_status(prim_k, z_sts)

                        # Step 3: Now send delayed Zombie Prewrite to Primary `acct_03` on Shard 0!
                        prim_pw = bytearray(_st.pack("<Q", z_sts))
                        prim_pw.extend(BinaryCodec.pack_bytes(prim_k))
                        prim_pw.extend(_st.pack("<QI", 20, 1))
                        prim_pw.append(OP_PUT)
                        prim_pw.extend(BinaryCodec.pack_bytes(prim_k))
                        prim_pw.extend(BinaryCodec.pack_opt_bytes(bogus_val))

                        prim_st, _ = adv_coord._shard_rpc(0, MSG_CLIENT_PREWRITE_REQ, bytes(prim_pw), _pw_parse, max_wait=2.0)
                        if prim_st == STATUS_TXN_ABORTED:
                            with stats_lock:
                                worker_stats["zombie_primary_prewrites_rejected"] += 1
                except Exception:
                    pass
                time.sleep(0.35)

        threads: List[threading.Thread] = []
        for wid in range(4):
            threads.append(threading.Thread(target=bank_transfer_worker, args=(wid,), daemon=True))
        for wid in range(2):
            threads.append(threading.Thread(target=write_skew_adversary_worker, args=(wid,), daemon=True))
        threads.append(threading.Thread(target=ro_global_audit_worker, daemon=True))
        for wid in range(4):
            threads.append(threading.Thread(target=linearizable_register_worker, args=(wid,), daemon=True))
        threads.append(threading.Thread(target=zombie_and_orphan_2pc_attacker, daemon=True))

        for t in threads:
            t.start()

        def find_shard_leader(sid: int) -> Optional[int]:
            for nid in shards_nodes[sid]:
                try:
                    st = query_node_status("127.0.0.1", real_node_ports[nid], timeout=0.4)
                    if st.role == 2:
                        return nid
                except Exception:
                    pass
            return None

        # =========================================================================
        # STAGE 1: L4 1~2 Byte TCP Micro-Fragmentation Storm across ALL links!
        # =========================================================================
        time.sleep(1.0)
        updated = set_chaos_policy("127.0.0.1", chaos_ctrl_port, "*", max_chunk_bytes=2, delay_ms=1)
        record_chaos_event("STAGE1_TCP_MICRO_FRAGMENTATION_ON", {"links_updated": updated, "max_chunk_bytes": 2})
        time.sleep(2.2)
        set_chaos_policy("127.0.0.1", chaos_ctrl_port, "*", max_chunk_bytes=0, delay_ms=0)
        record_chaos_event("STAGE1_TCP_MICRO_FRAGMENTATION_HEALED", {})

        # =========================================================================
        # STAGE 2: Asymmetric One-Way Partition on Shard 0 Leader!
        # Leader can send heartbeats to Follower A, CANNOT receive acks from A or B,
        # while A <-> B elect a new leader (`CheckQuorum` + `PreVote` + `ReadIndex`)!
        # =========================================================================
        s0_leader = find_shard_leader(0) or 0
        s0_others = [n for n in shards_nodes[0] if n != s0_leader]
        fa, fb = s0_others[0], s0_others[1]
        # Drop A -> Leader (one-way!) and bidirectional Leader <-> B, while keeping Leader -> A open!
        set_chaos_policy("127.0.0.1", chaos_ctrl_port, f"n{fa}->n{s0_leader}", drop_all=True)
        set_chaos_policy("127.0.0.1", chaos_ctrl_port, f"n{s0_leader}->n{fb}", drop_all=True)
        set_chaos_policy("127.0.0.1", chaos_ctrl_port, f"n{fb}->n{s0_leader}", drop_all=True)
        record_chaos_event(
            "STAGE2_ASYMMETRIC_PARTITION_ON",
            {
                "isolated_leader": s0_leader,
                "one_way_open": f"n{s0_leader}->n{fa}",
                "blackholed": [f"n{fa}->n{s0_leader}", f"n{s0_leader}<->n{fb}"],
            },
        )
        time.sleep(2.2)
        set_chaos_policy("127.0.0.1", chaos_ctrl_port, "*", drop_all=False, reset_existing=True)
        record_chaos_event("STAGE2_ASYMMETRIC_PARTITION_HEALED", {})
        time.sleep(1.0)

        # =========================================================================
        # STAGE 3: Zombie Leader `SIGSTOP` Freeze (1.3s) + `SIGCONT` Thaw on Shard 1!
        # =========================================================================
        s1_leader = find_shard_leader(1) or 10
        node_daemons[s1_leader].sigstop()
        record_chaos_event("STAGE3_SIGSTOP_ZOMBIE_LEADER", {"shard": 1, "frozen_node": s1_leader, "pid": node_daemons[s1_leader].pid()})
        time.sleep(1.4)
        node_daemons[s1_leader].sigcont()
        record_chaos_event("STAGE3_SIGCONT_ZOMBIE_LEADER_THAWED", {"shard": 1, "thawed_node": s1_leader})
        time.sleep(1.2)

        # =========================================================================
        # STAGE 4: Hard `SIGKILL` Assassination on TSO + Nodes + External Disk WAL
        #          Torn-Write Tail Corruption + OS Process Restart & Recovery!
        # =========================================================================
        victim_s0 = find_shard_leader(0) or 1
        victim_s1 = find_shard_leader(1) or 11

        tso_daemon.sigkill_and_wait()
        node_daemons[victim_s0].sigkill_and_wait()
        node_daemons[victim_s1].sigkill_and_wait()

        # Physically append incomplete/corrupt trailing bytes to both killed nodes' `raft_wal.log`
        # to exercise boot-time Torn-Write detection + `ftruncate` recovery on real ext4 files!
        torn_injected: Dict[int, int] = {}
        for vnid in (victim_s0, victim_s1):
            wal_file = node_data_dirs[vnid] / "raft_wal.log"
            with open(wal_file, "ab") as wf:
                wf.write(b"CWAL\xde\xad\xbe\xef\x99")
                wf.flush()
                os.fsync(wf.fileno())
            torn_injected[vnid] = 9

        record_chaos_event(
            "STAGE4_SIGKILL_AND_TORN_WAL_INJECTED",
            {
                "killed_tso": True,
                "killed_nodes": [victim_s0, victim_s1],
                "torn_wal_bytes_appended": torn_injected,
            },
        )

        # Restart TSO immediately (verifies monotonic +250 window jump!) and keep victim_s0 offline for 1.8s
        # so active Shard 0 leader advances >65 Raft entries and compacts WAL into Snapshot, forcing InstallSnapshot!
        new_tso_pid = tso_daemon.start()
        new_s1_pid = node_daemons[victim_s1].start()
        record_chaos_event("STAGE4_TSO_AND_S1_RESTARTED", {"new_tso_pid": new_tso_pid, "new_s1_pid": new_s1_pid})

        # Drive extra commits on Shard 0 while `victim_s0` is dead so `snapshot_index` advances!
        time.sleep(2.2)

        # =========================================================================
        # STAGE 5: Restart Lagging `victim_s0` -> Torn-WAL Recovery + `InstallSnapshot`
        #          Catch-Up + Drain Workers + Final Global Audit & Convergence Check!
        # =========================================================================
        new_s0_pid = node_daemons[victim_s0].start()
        record_chaos_event("STAGE5_S0_RESTARTED_FOR_SNAPSHOT_CATCHUP", {"node": victim_s0, "new_pid": new_s0_pid})
        time.sleep(2.2)

        stop_workers.set()
        for t in threads:
            t.join(timeout=5.0)

        # =========================================================================
        # STAGE 6: Quorum-Loss (`2/3` Followers `SIGSTOP`ped) Leader `ReadIndex`
        #          Fail-Closed Verification!
        # =========================================================================
        import struct as _st2

        quorum_fail_closed_ok = False
        active_s0_leader = find_shard_leader(0)
        if active_s0_leader is not None:
            frozen_followers = [n for n in shards_nodes[0] if n != active_s0_leader]
            for fnid in frozen_followers:
                node_daemons[fnid].sigstop()
            record_chaos_event(
                "STAGE6_QUORUM_LOSS_FOLLOWERS_FROZEN",
                {"leader": active_s0_leader, "frozen_followers": frozen_followers},
            )
            try:
                read_ts_probe = coord.alloc_ts(1)
                probe_payload = BinaryCodec.pack_bytes(b"acct_00") + _st2.pack("<Q", read_ts_probe)
                rtype, rbody = rpc_call(
                    "127.0.0.1",
                    real_node_ports[active_s0_leader],
                    MSG_CLIENT_READ_REQ,
                    probe_payload,
                    req_id=88888,
                    timeout=2.0,
                )
                if rtype == MSG_CLIENT_READ_RESP:
                    probe_status, _ = BinaryCodec.unpack_u8(rbody, 0)
                    # Leader WITHOUT quorum MUST NOT return STATUS_OK!
                    quorum_fail_closed_ok = probe_status != STATUS_OK
            except (TimeoutError, OSError):
                # Socket timeout because ReadIndex refused to complete without quorum -> fail-closed!
                quorum_fail_closed_ok = True
            finally:
                for fnid in frozen_followers:
                    node_daemons[fnid].sigcont()
            record_chaos_event(
                "STAGE6_QUORUM_RESTORED",
                {"quorum_fail_closed_verified": quorum_fail_closed_ok},
            )
            time.sleep(0.8)

        # Final quiescent Read-Only Global Audit after all chaos has healed
        final_tx_id = f"TX_FINAL_AUDIT_{next_uid()}"
        audit_keys = ACCOUNTS + [RESERVE_A, RESERVE_B]
        fin_inv = time.perf_counter_ns()
        fin_rts, fin_snap = coord.read_only_snapshot(audit_keys)
        fin_resp = time.perf_counter_ns()
        append_history(
            {
                "record_type": "txn",
                "tx_id": final_tx_id,
                "kind": "ro_audit",
                "committed": True,
                "inv_ns": fin_inv,
                "resp_ns": fin_resp,
                "reads": [
                    {"key": k.decode(), "val": fin_snap[k].decode() if fin_snap[k] is not None else None}
                    for k in audit_keys
                ],
                "writes": [],
            }
        )

        # Wait up to 3.0s for all 6 replicas to apply up to leader commit_index and check byte-identical state_crc32!
        convergence_ok = False
        replica_statuses: Dict[int, dict] = {}
        for _ in range(20):
            all_ready = True
            cur_statuses: Dict[int, NodeStatus] = {}
            for nid in all_nids:
                try:
                    cur_statuses[nid] = query_node_status("127.0.0.1", real_node_ports[nid], timeout=0.6)
                except Exception:
                    all_ready = False
                    break
            if all_ready:
                s0_crcs = {cur_statuses[n].state_crc32 for n in shards_nodes[0]}
                s1_crcs = {cur_statuses[n].state_crc32 for n in shards_nodes[1]}
                s0_applied = {cur_statuses[n].last_applied for n in shards_nodes[0]}
                s1_applied = {cur_statuses[n].last_applied for n in shards_nodes[1]}
                if len(s0_crcs) == 1 and len(s1_crcs) == 1 and len(s0_applied) == 1 and len(s1_applied) == 1:
                    convergence_ok = True
                    for nid, st in cur_statuses.items():
                        replica_statuses[nid] = {
                            "shard_id": st.shard_id,
                            "role": st.role,
                            "term": st.term,
                            "commit_index": st.commit_index,
                            "last_applied": st.last_applied,
                            "snapshot_index": st.snapshot_index,
                            "log_len": st.log_len,
                            "state_crc32": f"0x{st.state_crc32:08x}",
                        }
                    break
            time.sleep(0.15)

        if not replica_statuses:
            for nid in all_nids:
                try:
                    st = query_node_status("127.0.0.1", real_node_ports[nid], timeout=0.6)
                    replica_statuses[nid] = {
                        "shard_id": st.shard_id,
                        "role": st.role,
                        "term": st.term,
                        "commit_index": st.commit_index,
                        "last_applied": st.last_applied,
                        "snapshot_index": st.snapshot_index,
                        "log_len": st.log_len,
                        "state_crc32": f"0x{st.state_crc32:08x}",
                    }
                except Exception as e:
                    replica_statuses[nid] = {"error": str(e)}

        # Check WAL Torn-Write Recovery log evidence in killed nodes' stderr logs
        wal_recovery_logs: List[str] = []
        for vnid in (victim_s0, victim_s1):
            log_txt = (ws_run_dir / f"node_{vnid}.log").read_text(encoding="utf-8", errors="replace")
            for line in log_txt.splitlines():
                if "WAL-RECOVERY" in line or "Boot recovery" in line:
                    wal_recovery_logs.append(f"node_{vnid}: {line}")

        # Run External Independent Mathematical Oracle on `client_history.jsonl`!
        oracle_report = verify_history_file(str(history_path))

        snapshots_triggered = any(
            isinstance(v.get("snapshot_index"), int) and v["snapshot_index"] > 0
            for v in replica_statuses.values()
        )
        torn_recovery_verified = len(wal_recovery_logs) >= 2

        elapsed_s = round(time.monotonic() - t_campaign_start, 3)
        full_summary = {
            "run_id": run_id,
            "elapsed_seconds": elapsed_s,
            "worker_stats": worker_stats,
            "quorum_loss_fail_closed_verified": quorum_fail_closed_ok,
            "replica_convergence_verified": convergence_ok,
            "snapshots_compacted_verified": snapshots_triggered,
            "wal_torn_write_recovery_verified": torn_recovery_verified,
            "wal_recovery_evidence": wal_recovery_logs,
            "replica_statuses": replica_statuses,
            "oracle_verification": oracle_report,
        }
        with open(summary_path, "w", encoding="utf-8") as sf:
            json.dump(full_summary, sf, indent=2)

        print("\n" + "=" * 72)
        print("CHRONOS-KV CHAOS CAMPAIGN SUMMARY")
        print("=" * 72)
        print(json.dumps(full_summary, indent=2))
        print("=" * 72)

        all_passed = (
            bool(oracle_report["overall_valid"])
            and quorum_fail_closed_ok
            and worker_stats["zombie_primary_prewrites_rejected"] > 0
            and convergence_ok
            and snapshots_triggered
            and torn_recovery_verified
            and elapsed_s >= 5.0
        )
        return 0 if all_passed else 1

    finally:
        for d in reversed(daemons):
            d.terminate_clean()


if __name__ == "__main__":
    sys.exit(run_campaign())
