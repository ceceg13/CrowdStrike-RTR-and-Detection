#!/usr/bin/env python3
"""
FalconPy Project #3: Real‑Time Response Quick Shell
=================================================
Run a single RTR command (default *netstat*) against a CrowdStrike-managed
endpoint and save the output to a local text file.

Why this matters
----------------
Real‑Time Response (RTR) lets responders execute commands, pull files, or kill
processes on remote hosts—crucial for live incident handling. This script shows
how to:
1. **Create** an RTR session for a given device
2. **Run** one admin command (`netstat`, `ps`, `ipconfig`, etc.)
3. **Poll** for completion and **download** the stdout
4. **Close** the session

Quick start
-----------
```bash
pip install crowdstrike-falconpy
export FALCON_CLIENT_ID=XXXXXXXXXXXX
export FALCON_CLIENT_SECRET=YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY

# Replace <device_id> with the Falcon host's device ID (found in Host Details URL)
python falconpy_rtr_quick_shell.py <device_id> --cmd "ps aux" --outfile ps.txt
```

No credentials yet?  Use `--selftest` to run offline unit tests for helper
functions—they don't require a Falcon tenant.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import unittest
from pathlib import Path
from typing import Dict, List

# ---------------------------------------------------------------------------
# Optional dependency handling
# ---------------------------------------------------------------------------

aio_warning = (
    "[ERROR] Python package 'crowdstrike-falconpy' not found.\n"
    "Install it with:  pip install crowdstrike-falconpy"
)

try:
    from falconpy import RealTimeResponseAdmin  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    RealTimeResponseAdmin = None  # type: ignore[assignment]

# RTR command completes when status is one of these
_TERMINAL_STATES = {"complete", "failed", "cancelled"}

# ---------------------------------------------------------------------------
# RTR helpers
# ---------------------------------------------------------------------------

def connect_rtr() -> "RealTimeResponseAdmin":  # type: ignore[name-defined]
    """Return authenticated RTR Admin object or exit with hint."""
    if RealTimeResponseAdmin is None:
        sys.exit(aio_warning)

    cid = os.getenv("FALCON_CLIENT_ID")
    secret = os.getenv("FALCON_CLIENT_SECRET")
    cloud = os.getenv("FALCON_CLOUD", "us-1")
    if not cid or not secret:
        sys.exit("[ERROR] Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET env vars.")

    base_url = f"https://{cloud}.crowdstrike.com"
    return RealTimeResponseAdmin(client_id=cid, client_secret=secret, base_url=base_url)  # type: ignore[return-value]


def run_rtr_command(rtr: "RealTimeResponseAdmin", device_id: str, command: str, timeout: int = 60) -> str:
    """Execute *command* on *device_id*; return stdout as str."""
    # 1. Create session
    sess_resp = rtr.RTRAinitialize_session(body={"device_id": device_id})  # type: ignore[attr-defined]
    if sess_resp.get("status_code") != 201:
        raise RuntimeError(f"Session creation failed: {sess_resp}")
    session_id = sess_resp["body"]["resources"][0]["session_id"]

    # 2. Execute command
    cmd_resp = rtr.RTRAcommand(session_id=session_id, body={"command": command, "persist": True})  # type: ignore[attr-defined]
    if cmd_resp.get("status_code") != 201:
        raise RuntimeError(f"Command dispatch failed: {cmd_resp}")
    cloud_request_id = cmd_resp["body"]["resources"][0]["cloud_request_id"]

    # 3. Poll until done
    start = time.time()
    while time.time() - start < timeout:
        status_resp = rtr.RTRAget_command(session_id=session_id, cloud_request_id=cloud_request_id)  # type: ignore[attr-defined]
        state = status_resp["body"]["resources"][0]["stdout"]["status"]  # type: ignore[index]
        if state.lower() in _TERMINAL_STATES:
            stdout = status_resp["body"]["resources"][0]["stdout"]["content"]  # type: ignore[index]
            break
        time.sleep(2)
    else:
        raise TimeoutError("RTR command timed out.")

    # 4. Close session (best practice)
    rtr.RTRDeleteSession(session_id=session_id)  # type: ignore[attr-defined]
    return stdout

# ---------------------------------------------------------------------------
# Offline unit tests
# ---------------------------------------------------------------------------

class _FakeRTR:  # minimal stub for unit tests
    def __init__(self):
        self.called = []
    def RTRAinitialize_session(self, body):  # type: ignore
        self.called.append("init")
        return {"status_code": 201, "body": {"resources": [{"session_id": "S1"}]}}
    def RTRAcommand(self, session_id, body):  # type: ignore
        self.called.append("cmd")
        return {"status_code": 201, "body": {"resources": [{"cloud_request_id": "CR1"}]}}
    def RTRAget_command(self, session_id, cloud_request_id):  # type: ignore
        self.called.append("poll")
        return {"body": {"resources": [{"stdout": {"status": "complete", "content": "OK"}}]}}
    def RTRDeleteSession(self, session_id):  # type: ignore
        self.called.append("del")

class _RTRTests(unittest.TestCase):
    def test_happy_path(self):
        fake = _FakeRTR()
        output = run_rtr_command(fake, "123", "echo hi", timeout=5)
        self.assertEqual(output, "OK")
        self.assertEqual(fake.called, ["init", "cmd", "poll", "del"])

# ---------------------------------------------------------------------------
# Main CLI
# ---------------------------------------------------------------------------

def main(argv: List[str] | None = None):
    parser = argparse.ArgumentParser(description="Run a single RTR command and save stdout to a file")
    parser.add_argument("device_id", nargs="?", help="Falcon host device ID")
    parser.add_argument("--cmd", default="netstat -an", help="Command to run (default: 'netstat -an')")
    parser.add_argument("--outfile", default="rtr_output.txt", help="Where to save stdout")
    parser.add_argument("--timeout", type=int, default=60, help="Seconds to wait before giving up")
    parser.add_argument("--selftest", action="store_true", help="Run offline unit tests and exit")
    args = parser.parse_args(argv)

    if args.selftest:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(_RTRTests)
        unittest.TextTestRunner().run(suite)
        return

    if args.device_id is None:
        parser.error("device_id is required unless --selftest is used")

    rtr = connect_rtr()
    try:
        output = run_rtr_command(rtr, args.device_id, args.cmd, args.timeout)
    except Exception as exc:  # pylint: disable=broad-except
        sys.exit(f"[ERROR] {exc}")

    Path(args.outfile).write_text(output, encoding="utf-8")
    print(f"RTR command output saved to {args.outfile} (length {len(output)} bytes)")


if __name__ == "__main__":
    main()
