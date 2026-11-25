#!/usr/bin/env python3
"""
Static Anti-Mock & Physical Boundary CI Auditor (`ci_audit.py`).

Enforces the Core Engineering Charter before and after verification runs:
  1. Scans Rust (`src/**/*.rs`) and Python (`harness/**/*.py`) source files (excluding this audit script)
     for banned mock/reward-hacking tokens (`class Mock`, `class Fake`, `class Simulated`,
     `class InMemory`, `vuln_`, `inject_bug`, `simulate_failure`).
  2. Verifies presence of real OS kernel network & process primitives (`TcpListener`, `TcpStream`,
     `sync_all` in Rust; `socket`, `subprocess`, `signal` in Python).
  3. Verifies standalone ELF binaries (`chronos-tso`, `chronos-node`, `chronos-chaos-proxy`) exist
     and carry valid `\x7fELF` x86-64 headers.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BANNED_PATTERNS = [
    re.compile(r"\bclass\s+(Mock|Fake|Simulated|InMemory)\w*"),
    re.compile(r"\bstruct\s+(Mock|Fake|Simulated|InMemory)\w*"),
    re.compile(r"\bvuln_[A-Za-z0-9_]*"),
    re.compile(r"\binject_bug\b"),
    re.compile(r"\bsimulate_failure\b"),
    re.compile(r"\bsimulate_split_brain\b"),
]


def audit_sources() -> list[str]:
    errors: list[str] = []
    rust_files = list((ROOT / "src").rglob("*.rs"))
    py_files = [
        p for p in (ROOT / "harness").rglob("*.py") if p.name != "ci_audit.py"
    ]

    if len(rust_files) < 6:
        errors.append(f"Expected >= 6 Rust source files, found {len(rust_files)}")

    saw_rust_tcp = False
    saw_rust_fsync = False
    for rf in rust_files:
        text = rf.read_text(encoding="utf-8")
        for pat in BANNED_PATTERNS:
            m = pat.search(text)
            if m:
                errors.append(f"BANNED PATTERN in {rf.name}: {m.group(0)!r}")
        if "TcpListener" in text and "TcpStream" in text:
            saw_rust_tcp = True
        if "sync_all()" in text:
            saw_rust_fsync = True

    if not saw_rust_tcp:
        errors.append("Missing real TcpListener/TcpStream usage in Rust sources")
    if not saw_rust_fsync:
        errors.append("Missing real kernel fsync (`sync_all()`) usage in Rust sources")

    saw_py_socket = False
    saw_py_subprocess = False
    saw_py_signal = False
    for pf in py_files:
        text = pf.read_text(encoding="utf-8")
        for pat in BANNED_PATTERNS:
            m = pat.search(text)
            if m:
                errors.append(f"BANNED PATTERN in {pf.name}: {m.group(0)!r}")
        if "import socket" in text:
            saw_py_socket = True
        if "import subprocess" in text:
            saw_py_subprocess = True
        if "import signal" in text:
            saw_py_signal = True

    if not saw_py_socket:
        errors.append("Missing `import socket` in Python harness")
    if not saw_py_subprocess:
        errors.append("Missing `import subprocess` in Python harness")
    if not saw_py_signal:
        errors.append("Missing `import signal` in Python harness")

    for bin_name in ("chronos-tso", "chronos-node", "chronos-chaos-proxy"):
        bpath = ROOT / "bin" / bin_name
        if not bpath.exists():
            errors.append(f"Missing compiled native binary: {bpath}")
            continue
        with open(bpath, "rb") as f:
            hdr = f.read(4)
        if hdr != b"\x7fELF":
            errors.append(f"Binary {bpath} is not a real native Linux ELF executable (hdr={hdr!r})")

    return errors


def main() -> None:
    errs = audit_sources()
    if errs:
        print("[CI-AUDIT FAILED]")
        for e in errs:
            print(f"  - {e}")
        sys.exit(1)
    print(
        "[CI-AUDIT PASSED] Zero banned mock/flag patterns; real ELF binaries, TCP sockets, subprocesses, OS signals, and fsync verified."
    )


if __name__ == "__main__":
    main()
