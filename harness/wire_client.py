#!/usr/bin/env python3
"""
Binary Wire Client (`CKV1` framing + IEEE CRC32) & Strict-Serializable Percolator 2PC Coordinator.

Traverses real Linux kernel TCP loopback sockets (`127.0.0.1:port`) speaking exact `CKV1`
24-byte headers + little-endian binary payloads. Zero shared memory with Rust server processes.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
import zlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

WIRE_MAGIC = b"CKV1"
WIRE_VERSION = 1
HEADER_FMT = "<4sBBHQI"  # 20 bytes prefix before 4-byte CRC32
HEADER_LEN = 24

# Message Type Constants (matching src/protocol.rs)
MSG_TSO_ALLOC_REQ = 0x01
MSG_TSO_ALLOC_RESP = 0x02

MSG_CLIENT_READ_REQ = 0x20
MSG_CLIENT_READ_RESP = 0x21
MSG_CLIENT_PREWRITE_REQ = 0x22
MSG_CLIENT_PREWRITE_RESP = 0x23
MSG_CLIENT_COMMIT_REQ = 0x24
MSG_CLIENT_COMMIT_RESP = 0x25
MSG_CLIENT_ROLLBACK_REQ = 0x26
MSG_CLIENT_ROLLBACK_RESP = 0x27
MSG_CLIENT_CHECK_TXN_REQ = 0x28
MSG_CLIENT_CHECK_TXN_RESP = 0x29
MSG_CLIENT_NODE_STATUS_REQ = 0x2A
MSG_CLIENT_NODE_STATUS_RESP = 0x2B
MSG_CLIENT_RAW_CAS_REQ = 0x2C
MSG_CLIENT_RAW_CAS_RESP = 0x2D
MSG_CLIENT_RAW_GET_REQ = 0x2E
MSG_CLIENT_RAW_GET_RESP = 0x2F

MSG_CHAOS_SET_POLICY_REQ = 0x40
MSG_CHAOS_SET_POLICY_RESP = 0x41

# Status Enums
STATUS_OK = 0
STATUS_NOT_LEADER = 1
STATUS_KEY_LOCKED = 2
STATUS_WRITE_CONFLICT = 3
STATUS_TXN_ABORTED = 4
STATUS_TIMEOUT = 5
STATUS_BAD_REQUEST = 6

# LockOp Enums
OP_PUT = 1
OP_DELETE = 2
OP_READ_LOCK = 3

# TxnStatusAction Enums
ACTION_ALREADY_COMMITTED = 1
ACTION_ALREADY_ROLLED_BACK = 2
ACTION_TTL_EXPIRED_ROLLED_BACK = 3
ACTION_MISSING_PRIMARY_ROLLED_BACK = 4
ACTION_LOCK_ALIVE = 5


class WireProtocolError(Exception):
    pass


class BinaryCodec:
    @staticmethod
    def pack_bytes(b: bytes) -> bytes:
        return struct.pack("<I", len(b)) + b

    @staticmethod
    def pack_str(s: str) -> bytes:
        return BinaryCodec.pack_bytes(s.encode("utf-8"))

    @staticmethod
    def pack_opt_bytes(opt: Optional[bytes]) -> bytes:
        if opt is None:
            return b"\x00"
        return b"\x01" + BinaryCodec.pack_bytes(opt)

    @staticmethod
    def unpack_u8(buf: bytes, pos: int) -> Tuple[int, int]:
        if pos + 1 > len(buf):
            raise WireProtocolError("underflow u8")
        return buf[pos], pos + 1

    @staticmethod
    def unpack_bool(buf: bytes, pos: int) -> Tuple[bool, int]:
        v, pos = BinaryCodec.unpack_u8(buf, pos)
        if v not in (0, 1):
            raise WireProtocolError(f"invalid bool tag {v}")
        return (v == 1), pos

    @staticmethod
    def unpack_u16(buf: bytes, pos: int) -> Tuple[int, int]:
        if pos + 2 > len(buf):
            raise WireProtocolError("underflow u16")
        return struct.unpack_from("<H", buf, pos)[0], pos + 2

    @staticmethod
    def unpack_u32(buf: bytes, pos: int) -> Tuple[int, int]:
        if pos + 4 > len(buf):
            raise WireProtocolError("underflow u32")
        return struct.unpack_from("<I", buf, pos)[0], pos + 4

    @staticmethod
    def unpack_u64(buf: bytes, pos: int) -> Tuple[int, int]:
        if pos + 8 > len(buf):
            raise WireProtocolError("underflow u64")
        return struct.unpack_from("<Q", buf, pos)[0], pos + 8

    @staticmethod
    def unpack_bytes(buf: bytes, pos: int) -> Tuple[bytes, int]:
        length, pos = BinaryCodec.unpack_u32(buf, pos)
        if pos + length > len(buf):
            raise WireProtocolError("underflow bytes")
        return buf[pos : pos + length], pos + length

    @staticmethod
    def unpack_str(buf: bytes, pos: int) -> Tuple[str, int]:
        raw, pos = BinaryCodec.unpack_bytes(buf, pos)
        return raw.decode("utf-8"), pos

    @staticmethod
    def unpack_opt_bytes(buf: bytes, pos: int) -> Tuple[Optional[bytes], int]:
        present, pos = BinaryCodec.unpack_bool(buf, pos)
        if not present:
            return None, pos
        return BinaryCodec.unpack_bytes(buf, pos)

    @staticmethod
    def unpack_opt_u16(buf: bytes, pos: int) -> Tuple[Optional[int], int]:
        present, pos = BinaryCodec.unpack_bool(buf, pos)
        if not present:
            return None, pos
        return BinaryCodec.unpack_u16(buf, pos)


def encode_frame(msg_type: int, req_id: int, payload: bytes, flags: int = 0) -> bytes:
    prefix = struct.pack(HEADER_FMT, WIRE_MAGIC, WIRE_VERSION, msg_type, flags, req_id, len(payload))
    crc = zlib.crc32(prefix)
    crc = zlib.crc32(payload, crc) & 0xFFFFFFFF
    return prefix + struct.pack("<I", crc) + payload


def recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < n:
        part = sock.recv(n - len(chunks))
        if not part:
            raise EOFError(f"socket closed mid-frame ({len(chunks)}/{n} bytes)")
        chunks.extend(part)
    return bytes(chunks)


def rpc_call(host: str, port: int, msg_type: int, payload: bytes, req_id: int = 1, timeout: float = 2.0) -> Tuple[int, bytes]:
    raw_req = encode_frame(msg_type, req_id, payload)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(timeout)
        sock.sendall(raw_req)
        hdr = recv_exact(sock, HEADER_LEN)
        magic, ver, resp_type, _flags, resp_req_id, plen = struct.unpack(HEADER_FMT, hdr[:20])
        expected_crc = struct.unpack("<I", hdr[20:24])[0]
        if magic != WIRE_MAGIC or ver != WIRE_VERSION:
            raise WireProtocolError(f"bad response header magic={magic!r} ver={ver}")
        body = recv_exact(sock, plen) if plen > 0 else b""
        actual_crc = zlib.crc32(body, zlib.crc32(hdr[:20])) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise WireProtocolError(f"CRC32 mismatch expected=0x{expected_crc:08x} actual=0x{actual_crc:08x}")
        if resp_req_id != req_id:
            raise WireProtocolError(f"req_id mismatch {resp_req_id} != {req_id}")
        return resp_type, body


@dataclass
class LockInfo:
    key: bytes
    primary_key: bytes
    start_ts: int
    ttl_ts: int
    op: int

    @staticmethod
    def unpack_from(buf: bytes, pos: int) -> Tuple["LockInfo", int]:
        key, pos = BinaryCodec.unpack_bytes(buf, pos)
        primary, pos = BinaryCodec.unpack_bytes(buf, pos)
        sts, pos = BinaryCodec.unpack_u64(buf, pos)
        ttl, pos = BinaryCodec.unpack_u64(buf, pos)
        op, pos = BinaryCodec.unpack_u8(buf, pos)
        return LockInfo(key, primary, sts, ttl, op), pos


@dataclass
class NodeStatus:
    node_id: int
    shard_id: int
    role: int
    term: int
    commit_index: int
    last_applied: int
    snapshot_index: int
    log_len: int
    state_crc32: int
    leader_hint: Optional[int]


def query_node_status(host: str, port: int, timeout: float = 0.8) -> NodeStatus:
    rtype, body = rpc_call(host, port, MSG_CLIENT_NODE_STATUS_REQ, b"", req_id=77, timeout=timeout)
    if rtype != MSG_CLIENT_NODE_STATUS_RESP:
        raise WireProtocolError(f"unexpected status resp {rtype}")
    pos = 0
    nid, pos = BinaryCodec.unpack_u16(body, pos)
    sid, pos = BinaryCodec.unpack_u16(body, pos)
    role, pos = BinaryCodec.unpack_u8(body, pos)
    term, pos = BinaryCodec.unpack_u64(body, pos)
    cidx, pos = BinaryCodec.unpack_u64(body, pos)
    lapp, pos = BinaryCodec.unpack_u64(body, pos)
    sidx, pos = BinaryCodec.unpack_u64(body, pos)
    llen, pos = BinaryCodec.unpack_u64(body, pos)
    scrc, pos = BinaryCodec.unpack_u32(body, pos)
    lhint, pos = BinaryCodec.unpack_opt_u16(body, pos)
    return NodeStatus(nid, sid, role, term, cidx, lapp, sidx, llen, scrc, lhint)


def set_chaos_policy(
    ctrl_host: str,
    ctrl_port: int,
    link_name: str,
    drop_all: bool = False,
    delay_ms: int = 0,
    max_chunk_bytes: int = 0,
    reset_existing: bool = False,
) -> int:
    payload = (
        BinaryCodec.pack_str(link_name)
        + (b"\x01" if drop_all else b"\x00")
        + struct.pack("<II", delay_ms, max_chunk_bytes)
        + (b"\x01" if reset_existing else b"\x00")
    )
    rtype, body = rpc_call(ctrl_host, ctrl_port, MSG_CHAOS_SET_POLICY_REQ, payload, req_id=9, timeout=2.0)
    if rtype != MSG_CHAOS_SET_POLICY_RESP:
        raise WireProtocolError("bad chaos policy resp")
    cnt, _ = BinaryCodec.unpack_u32(body, 0)
    return cnt


class TxConflictRetry(Exception):
    pass


class ChronosCoordinator:
    """
    Thread-safe Strict-Serializable Percolator 2PC Coordinator & Linearizable Register Client.
    Shard Routing:
      - Keys < b"m" (e.g. b"acct_00"..b"acct_04", b"res_a", b"reg_0") -> Shard 0
      - Keys >= b"m" (e.g. b"m_acct_05"..b"m_acct_09", b"m_res_b", b"m_reg_1") -> Shard 1
    """

    def __init__(
        self,
        tso_addr: Tuple[str, int],
        shard_endpoints: Dict[int, Dict[int, Tuple[str, int]]],
        lock_ttl_ts: int = 80,
    ):
        self.tso_addr = tso_addr
        self.shard_endpoints = shard_endpoints
        self.lock_ttl_ts = lock_ttl_ts
        self._leader_cache: Dict[int, int] = {sid: sorted(nodes.keys())[0] for sid, nodes in shard_endpoints.items()}
        self._lock = threading.Lock()
        self._req_seq = 100

    def _next_req_id(self) -> int:
        with self._lock:
            self._req_seq += 1
            return self._req_seq

    @staticmethod
    def shard_for_key(key: bytes) -> int:
        return 0 if key < b"m_" else 1

    def alloc_ts(self, count: int = 1, max_wait: float = 6.0) -> int:
        deadline = time.monotonic() + max_wait
        payload = struct.pack("<I", count)
        last_err: Optional[Exception] = None
        while time.monotonic() < deadline:
            try:
                rtype, body = rpc_call(
                    self.tso_addr[0],
                    self.tso_addr[1],
                    MSG_TSO_ALLOC_REQ,
                    payload,
                    req_id=self._next_req_id(),
                    timeout=0.8,
                )
                if rtype == MSG_TSO_ALLOC_RESP:
                    base_ts, _cnt = struct.unpack("<QI", body[:12])
                    return base_ts
            except Exception as e:
                last_err = e
                time.sleep(0.03)
        raise TimeoutError(f"TSO allocation timed out: {last_err}")

    def _shard_rpc(
        self,
        shard_id: int,
        msg_type: int,
        payload: bytes,
        parse_status_and_hint,
        max_wait: float = 5.0,
    ):
        deadline = time.monotonic() + max_wait
        nodes = self.shard_endpoints[shard_id]
        node_ids = sorted(nodes.keys())
        idx = 0

        while time.monotonic() < deadline:
            with self._lock:
                preferred = self._leader_cache.get(shard_id, node_ids[0])
            order = [preferred] + [nid for nid in node_ids if nid != preferred]
            target_nid = order[idx % len(order)]
            host, port = nodes[target_nid]

            try:
                rtype, body = rpc_call(
                    host,
                    port,
                    msg_type,
                    payload,
                    req_id=self._next_req_id(),
                    timeout=1.4,
                )
                status, leader_hint, parsed = parse_status_and_hint(rtype, body)
                if status == STATUS_NOT_LEADER or status == STATUS_TIMEOUT:
                    if leader_hint is not None and leader_hint in nodes:
                        with self._lock:
                            self._leader_cache[shard_id] = leader_hint
                        idx = 0
                    else:
                        idx += 1
                    time.sleep(0.02)
                    continue
                with self._lock:
                    self._leader_cache[shard_id] = target_nid
                return status, parsed
            except Exception:
                idx += 1
                time.sleep(0.025)

        raise TimeoutError(f"Shard {shard_id} RPC 0x{msg_type:02x} timed out across all replicas")

    def check_txn_status(self, primary_key: bytes, lock_start_ts: int) -> Tuple[int, int]:
        caller_ts = self.alloc_ts(1)
        shard_id = self.shard_for_key(primary_key)
        payload = BinaryCodec.pack_bytes(primary_key) + struct.pack("<QQ", lock_start_ts, caller_ts)

        def parser(rtype: int, body: bytes):
            if rtype != MSG_CLIENT_CHECK_TXN_RESP:
                raise WireProtocolError(f"unexpected check_txn resp {rtype}")
            pos = 0
            st, pos = BinaryCodec.unpack_u8(body, pos)
            act, pos = BinaryCodec.unpack_u8(body, pos)
            cts, pos = BinaryCodec.unpack_u64(body, pos)
            hint, pos = BinaryCodec.unpack_opt_u16(body, pos)
            return st, hint, (act, cts)

        st, (action, commit_ts) = self._shard_rpc(shard_id, MSG_CLIENT_CHECK_TXN_REQ, payload, parser)
        if st != STATUS_OK:
            raise TxConflictRetry(f"check_txn_status failed status={st}")
        return action, commit_ts

    def _send_commit_shard(self, shard_id: int, start_ts: int, commit_ts: int, keys: List[bytes], max_wait: float = 5.0) -> Tuple[int, str]:
        payload = bytearray(struct.pack("<QQI", start_ts, commit_ts, len(keys)))
        for k in keys:
            payload.extend(BinaryCodec.pack_bytes(k))

        def parser(rtype: int, body: bytes):
            if rtype != MSG_CLIENT_COMMIT_RESP:
                raise WireProtocolError(f"unexpected commit resp {rtype}")
            pos = 0
            st, pos = BinaryCodec.unpack_u8(body, pos)
            reason, pos = BinaryCodec.unpack_str(body, pos)
            hint, pos = BinaryCodec.unpack_opt_u16(body, pos)
            return st, hint, reason

        return self._shard_rpc(shard_id, MSG_CLIENT_COMMIT_REQ, bytes(payload), parser, max_wait=max_wait)

    def _send_rollback_shard(self, shard_id: int, start_ts: int, keys: List[bytes], max_wait: float = 3.0) -> int:
        payload = bytearray(struct.pack("<QI", start_ts, len(keys)))
        for k in keys:
            payload.extend(BinaryCodec.pack_bytes(k))

        def parser(rtype: int, body: bytes):
            if rtype != MSG_CLIENT_ROLLBACK_RESP:
                raise WireProtocolError(f"unexpected rollback resp {rtype}")
            pos = 0
            st, pos = BinaryCodec.unpack_u8(body, pos)
            hint, pos = BinaryCodec.unpack_opt_u16(body, pos)
            return st, hint, None

        st, _ = self._shard_rpc(shard_id, MSG_CLIENT_ROLLBACK_REQ, bytes(payload), parser, max_wait=max_wait)
        return st

    def resolve_lock(self, lock: LockInfo) -> None:
        """Resolves an encountered MVCC lock by consulting its Primary key via CheckTxnStatus."""
        action, commit_ts = self.check_txn_status(lock.primary_key, lock.start_ts)
        key_shard = self.shard_for_key(lock.key)
        if action == ACTION_ALREADY_COMMITTED:
            self._send_commit_shard(key_shard, lock.start_ts, commit_ts, [lock.key], max_wait=3.0)
        elif action in (
            ACTION_ALREADY_ROLLED_BACK,
            ACTION_TTL_EXPIRED_ROLLED_BACK,
            ACTION_MISSING_PRIMARY_ROLLED_BACK,
        ):
            self._send_rollback_shard(key_shard, lock.start_ts, [lock.key], max_wait=3.0)
        elif action == ACTION_LOCK_ALIVE:
            # Advance TSO logical time gently and sleep briefly so live transaction can finish or TTL can expire
            time.sleep(0.015)
            self.alloc_ts(20)

    def mvcc_get(self, key: bytes, read_ts: int, max_wait: float = 6.0) -> Optional[bytes]:
        shard_id = self.shard_for_key(key)
        payload = BinaryCodec.pack_bytes(key) + struct.pack("<Q", read_ts)

        def parser(rtype: int, body: bytes):
            if rtype != MSG_CLIENT_READ_RESP:
                raise WireProtocolError(f"unexpected read resp {rtype}")
            pos = 0
            st, pos = BinaryCodec.unpack_u8(body, pos)
            val, pos = BinaryCodec.unpack_opt_bytes(body, pos)
            has_lock, pos = BinaryCodec.unpack_bool(body, pos)
            lk = None
            if has_lock:
                lk, pos = LockInfo.unpack_from(body, pos)
            hint, pos = BinaryCodec.unpack_opt_u16(body, pos)
            return st, hint, (val, lk)

        deadline = time.monotonic() + max_wait
        while time.monotonic() < deadline:
            st, (val, lk) = self._shard_rpc(shard_id, MSG_CLIENT_READ_REQ, payload, parser, max_wait=3.0)
            if st == STATUS_OK:
                return val
            if st == STATUS_KEY_LOCKED and lk is not None:
                self.resolve_lock(lk)
                continue
            raise WireProtocolError(f"mvcc_get unexpected status={st}")
        raise TimeoutError(f"mvcc_get lock resolution timed out for key={key!r} at read_ts={read_ts}")

    def read_only_snapshot(self, keys: List[bytes]) -> Tuple[int, Dict[bytes, Optional[bytes]]]:
        """Executes a multi-shard Strict-Serializable Read-Only transaction at a single TSO `read_ts`."""
        read_ts = self.alloc_ts(1)
        out: Dict[bytes, Optional[bytes]] = {}
        for k in keys:
            out[k] = self.mvcc_get(k, read_ts)
        return read_ts, out

    def execute_rw_txn(self, fn, max_retries: int = 30):
        """
        Executes `fn(tx)` under Strict Serializability (`1SR + Real-Time Order`):
        - Every read (`None` or present) is recorded in `read_set`.
        - `all_keys = sorted(read_set | writes.keys())`, `primary_key = all_keys[0]`.
        - Primary shard is always Prewritten first; Read-only keys in a RW txn receive `OP_READ_LOCK`.
        - Ambiguous Primary Commit errors are deterministically resolved via `CheckTxnStatus`!
        """
        for attempt in range(max_retries):
            start_ts = self.alloc_ts(1)
            tx = _RwTxnContext(self, start_ts)
            try:
                user_ret = fn(tx)
                if not tx.writes:
                    return start_ts, start_ts, user_ret

                all_keys = sorted(tx.read_set | set(tx.writes.keys()))
                primary_key = all_keys[0]
                primary_shard = self.shard_for_key(primary_key)

                # Group mutations by shard, deduplicating reads ∩ writes so Put/Delete wins over ReadLock
                shard_mutations: Dict[int, List[Tuple[int, bytes, Optional[bytes]]]] = {}
                for k in all_keys:
                    sid = self.shard_for_key(k)
                    if k in tx.writes:
                        op, val = tx.writes[k]
                    else:
                        op, val = OP_READ_LOCK, None
                    shard_mutations.setdefault(sid, []).append((op, k, val))

                # Order shards so Primary shard is ALWAYS prewritten first!
                ordered_shards = [primary_shard] + [s for s in sorted(shard_mutations.keys()) if s != primary_shard]
                locked_shards: List[int] = []

                for sid in ordered_shards:
                    muts = shard_mutations[sid]
                    pw_payload = bytearray(struct.pack("<Q", start_ts))
                    pw_payload.extend(BinaryCodec.pack_bytes(primary_key))
                    pw_payload.extend(struct.pack("<QI", self.lock_ttl_ts, len(muts)))
                    for op, k, val in muts:
                        pw_payload.append(op)
                        pw_payload.extend(BinaryCodec.pack_bytes(k))
                        pw_payload.extend(BinaryCodec.pack_opt_bytes(val))

                    def pw_parser(rtype: int, body: bytes):
                        if rtype != MSG_CLIENT_PREWRITE_RESP:
                            raise WireProtocolError(f"unexpected prewrite resp {rtype}")
                        pos = 0
                        st, pos = BinaryCodec.unpack_u8(body, pos)
                        reason, pos = BinaryCodec.unpack_str(body, pos)
                        has_lk, pos = BinaryCodec.unpack_bool(body, pos)
                        blk = None
                        if has_lk:
                            blk, pos = LockInfo.unpack_from(body, pos)
                        hint, pos = BinaryCodec.unpack_opt_u16(body, pos)
                        return st, hint, (reason, blk)

                    st, (reason, blk) = self._shard_rpc(sid, MSG_CLIENT_PREWRITE_REQ, bytes(pw_payload), pw_parser)
                    if st != STATUS_OK:
                        # Rollback already prewritten shards before retrying
                        for prev_sid in locked_shards:
                            prev_keys = [m[1] for m in shard_mutations[prev_sid]]
                            try:
                                self._send_rollback_shard(prev_sid, start_ts, prev_keys, max_wait=1.5)
                            except Exception:
                                pass
                        if st == STATUS_KEY_LOCKED and blk is not None:
                            try:
                                self.resolve_lock(blk)
                            except Exception:
                                pass
                        raise TxConflictRetry(f"prewrite conflict st={st}: {reason}")

                    locked_shards.append(sid)

                # Phase 2: Allocate commit_ts from TSO and commit Primary shard (Atomic Commit Point!)
                commit_ts = self.alloc_ts(1)
                primary_keys = [m[1] for m in shard_mutations[primary_shard]]

                committed = False
                try:
                    cst, creason = self._send_commit_shard(primary_shard, start_ts, commit_ts, primary_keys, max_wait=4.0)
                    if cst == STATUS_OK:
                        committed = True
                    else:
                        # Primary rejected commit (e.g. lock expired and rolled back before commit arrived)
                        for sec_sid in ordered_shards[1:]:
                            sec_keys = [m[1] for m in shard_mutations[sec_sid]]
                            try:
                                self._send_rollback_shard(sec_sid, start_ts, sec_keys, max_wait=1.5)
                            except Exception:
                                pass
                        raise TxConflictRetry(f"primary commit rejected st={cst}: {creason}")
                except TimeoutError:
                    # Ambiguous Primary outcome under SIGKILL/partition -> consult CheckTxnStatus truth!
                    while True:
                        act, actual_cts = self.check_txn_status(primary_key, start_ts)
                        if act == ACTION_ALREADY_COMMITTED:
                            commit_ts = actual_cts
                            committed = True
                            break
                        if act in (
                            ACTION_ALREADY_ROLLED_BACK,
                            ACTION_TTL_EXPIRED_ROLLED_BACK,
                            ACTION_MISSING_PRIMARY_ROLLED_BACK,
                        ):
                            for sec_sid in ordered_shards[1:]:
                                sec_keys = [m[1] for m in shard_mutations[sec_sid]]
                                try:
                                    self._send_rollback_shard(sec_sid, start_ts, sec_keys, max_wait=1.5)
                                except Exception:
                                    pass
                            raise TxConflictRetry("primary rolled back after ambiguous timeout")
                        # Lock still alive on primary -> retry primary commit once
                        try:
                            cst2, _ = self._send_commit_shard(primary_shard, start_ts, commit_ts, primary_keys, max_wait=2.0)
                            if cst2 == STATUS_OK:
                                committed = True
                                break
                        except Exception:
                            time.sleep(0.03)

                assert committed
                # Best-effort synchronous commit of Secondary shards (if dropped, future readers resolve via Primary!)
                for sec_sid in ordered_shards[1:]:
                    sec_keys = [m[1] for m in shard_mutations[sec_sid]]
                    try:
                        self._send_commit_shard(sec_sid, start_ts, commit_ts, sec_keys, max_wait=2.0)
                    except Exception:
                        pass

                return start_ts, commit_ts, user_ret

            except (TxConflictRetry, TimeoutError, WireProtocolError):
                backoff = min(0.008 * (1.35 ** min(attempt, 8)), 0.12)
                time.sleep(backoff)
                continue

        raise RuntimeError(f"Transaction exhausted {max_retries} retries under contention/chaos")

    def raw_cas(self, key: bytes, expected: Optional[bytes], desired: bytes, op_uid: int) -> Tuple[bool, Optional[bytes]]:
        shard_id = self.shard_for_key(key)
        payload = (
            BinaryCodec.pack_bytes(key)
            + BinaryCodec.pack_opt_bytes(expected)
            + BinaryCodec.pack_bytes(desired)
            + struct.pack("<Q", op_uid)
        )

        def parser(rtype: int, body: bytes):
            if rtype != MSG_CLIENT_RAW_CAS_RESP:
                raise WireProtocolError(f"unexpected raw_cas resp {rtype}")
            pos = 0
            st, pos = BinaryCodec.unpack_u8(body, pos)
            swapped, pos = BinaryCodec.unpack_bool(body, pos)
            prev, pos = BinaryCodec.unpack_opt_bytes(body, pos)
            hint, pos = BinaryCodec.unpack_opt_u16(body, pos)
            return st, hint, (swapped, prev)

        st, (swapped, prev) = self._shard_rpc(shard_id, MSG_CLIENT_RAW_CAS_REQ, payload, parser, max_wait=6.0)
        if st != STATUS_OK:
            raise WireProtocolError(f"raw_cas failed status={st}")
        return swapped, prev

    def raw_get(self, key: bytes) -> Optional[bytes]:
        shard_id = self.shard_for_key(key)
        payload = BinaryCodec.pack_bytes(key)

        def parser(rtype: int, body: bytes):
            if rtype != MSG_CLIENT_RAW_GET_RESP:
                raise WireProtocolError(f"unexpected raw_get resp {rtype}")
            pos = 0
            st, pos = BinaryCodec.unpack_u8(body, pos)
            val, pos = BinaryCodec.unpack_opt_bytes(body, pos)
            hint, pos = BinaryCodec.unpack_opt_u16(body, pos)
            return st, hint, val

        st, val = self._shard_rpc(shard_id, MSG_CLIENT_RAW_GET_REQ, payload, parser, max_wait=6.0)
        if st != STATUS_OK:
            raise WireProtocolError(f"raw_get failed status={st}")
        return val


class _RwTxnContext:
    def __init__(self, coord: ChronosCoordinator, start_ts: int):
        self.coord = coord
        self.start_ts = start_ts
        self.read_set: set[bytes] = set()
        self.read_cache: Dict[bytes, Optional[bytes]] = {}
        self.writes: Dict[bytes, Tuple[int, Optional[bytes]]] = {}

    def get(self, key: bytes) -> Optional[bytes]:
        if key in self.writes:
            op, val = self.writes[key]
            return val if op == OP_PUT else None
        if key in self.read_cache:
            return self.read_cache[key]
        val = self.coord.mvcc_get(key, self.start_ts)
        # CRITICAL: Always record `key` in `read_set` EVEN IF `val is None`!
        self.read_set.add(key)
        self.read_cache[key] = val
        return val

    def put(self, key: bytes, value: bytes) -> None:
        self.writes[key] = (OP_PUT, value)

    def delete(self, key: bytes) -> None:
        self.writes[key] = (OP_DELETE, None)
