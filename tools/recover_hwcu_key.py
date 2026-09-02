#!/usr/bin/env python3
"""Offline recovery of an owner-authorized numeric HWCU DES key from a PCAP.

The program intentionally never prints the recovered key or packet contents.
On a match it writes the key only to the app's private LocalSecretStore and
emits a small status JSON document suitable for monitoring a long local run.
"""

from __future__ import annotations

import argparse
import binascii
import json
import multiprocessing as mp
import re
import sys
import time
import urllib.parse
from pathlib import Path
from queue import Empty

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from Crypto.Cipher import DES

from services.stb_discovery_service import _reassemble_tcp_streams
from services.storage_service import LocalSecretStore


_AUTHENTICATOR_RE = re.compile(rb"(?:^|[?&\r\n])Authenticator=([^&\s\r\n]+)", re.IGNORECASE)
_PLAIN_PREFIX_RE = re.compile(rb"^[0-9]{8}\$")
_PLAIN_SUFFIX = b"$$CTC"


def _authenticator_blocks(pcap_path: Path) -> list[bytes]:
    raw = b"\n".join(_reassemble_tcp_streams(str(pcap_path)).values())
    blocks: list[bytes] = []
    for item in _AUTHENTICATOR_RE.findall(raw):
        try:
            value = urllib.parse.unquote_plus(item.decode("ascii")).strip()
            ciphertext = binascii.unhexlify(value)
        except (UnicodeDecodeError, ValueError, binascii.Error):
            continue
        if len(ciphertext) >= 8 and len(ciphertext) % 8 == 0:
            blocks.append(ciphertext)
    if not blocks:
        raise ValueError("PCAP 中未找到可验证的 HWCU Authenticator")
    return blocks


def _matches_key(key: bytes, ciphertexts: list[bytes]) -> bool:
    """Validate with protocol structure, without ever exposing plaintext."""
    cipher = DES.new(key, DES.MODE_ECB)
    for ciphertext in ciphertexts:
        # The fixed ``8 decimal digits + '$'`` prefix crosses the DES block
        # boundary, so validate the first two blocks before decrypting all.
        first = cipher.decrypt(ciphertext[:16])
        if not _PLAIN_PREFIX_RE.match(first):
            continue
        plaintext = cipher.decrypt(ciphertext)
        if plaintext.startswith(first) and _PLAIN_SUFFIX in plaintext:
            return True
    return False


def _worker(start: int, end: int, ciphertexts: list[bytes], found: mp.Event, queue: mp.Queue) -> None:
    checked = 0
    reported = 0
    for number in range(start, end):
        if found.is_set():
            break
        key = f"{number:08d}".encode("ascii")
        checked += 1
        if _matches_key(key, ciphertexts):
            found.set()
            queue.put(("found", key.decode("ascii"), checked - reported))
            return
        if checked % 250_000 == 0:
            queue.put(("progress", "", checked - reported))
            reported = checked
    queue.put(("done", "", checked - reported))


def _write_status(path: Path, **payload: object) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    temp.replace(path)


def recover_numeric_key(
    pcap_path: Path,
    secret_path: Path,
    status_path: Path,
    *,
    start: int = 0,
    end: int = 100_000_000,
    workers: int = 1,
) -> bool:
    if not (0 <= start < end <= 100_000_000):
        raise ValueError("候选范围必须位于 00000000 到 99999999")
    ciphertexts = _authenticator_blocks(pcap_path)
    workers = max(1, min(int(workers), end - start))
    started_at = int(time.time())
    _write_status(status_path, status="running", checked=0, total=end - start, workers=workers, started_at=started_at)

    found = mp.Event()
    queue: mp.Queue = mp.Queue()
    width = (end - start + workers - 1) // workers
    processes = [
        mp.Process(target=_worker, args=(offset, min(end, offset + width), ciphertexts, found, queue))
        for offset in range(start, end, width)
    ]
    for process in processes:
        process.start()

    checked = 0
    key = ""
    remaining = len(processes)
    while remaining:
        try:
            kind, candidate, increment = queue.get(timeout=1)
            checked += int(increment)
            if kind == "found":
                key = candidate
                break
            if kind == "done":
                remaining -= 1
            _write_status(status_path, status="running", checked=checked, total=end - start, workers=workers, started_at=started_at)
        except Empty:
            _write_status(status_path, status="running", checked=checked, total=end - start, workers=workers, started_at=started_at)
    found.set()
    for process in processes:
        process.join(timeout=5)
        if process.is_alive():
            process.terminate()
            process.join()
    if key:
        LocalSecretStore(secret_path).set_epg_key(key)
        _write_status(status_path, status="found", checked=checked, total=end - start, workers=workers, started_at=started_at, finished_at=int(time.time()))
        return True
    _write_status(status_path, status="not_found", checked=checked, total=end - start, workers=workers, started_at=started_at, finished_at=int(time.time()))
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline numeric HWCU key recovery")
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--secret-path", type=Path, default=Path("/app/data/epg-key.secret"))
    parser.add_argument("--status-path", type=Path, default=Path("/app/data/epg-key-recovery-status.json"))
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--end", type=int, default=100_000_000)
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args()
    return 0 if recover_numeric_key(args.pcap, args.secret_path, args.status_path, start=args.start, end=args.end, workers=args.workers) else 2


if __name__ == "__main__":
    raise SystemExit(main())
