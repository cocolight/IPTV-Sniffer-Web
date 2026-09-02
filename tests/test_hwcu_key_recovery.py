"""Tests for the owner-local, offline HWCU numeric key recovery helper."""

import importlib.util
from pathlib import Path

from Crypto.Cipher import DES


_SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "recover_hwcu_key.py"
_SPEC = importlib.util.spec_from_file_location("recover_hwcu_key", _SCRIPT)
recovery = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(recovery)


def test_offline_numeric_recovery_saves_match_without_printing_key(tmp_path, monkeypatch):
    key = b"00000042"
    plaintext = b"12345678$challenge$userid$stbid$ip$mac$$CTC".ljust(48, b"\x00")
    ciphertext = DES.new(key, DES.MODE_ECB).encrypt(plaintext)
    monkeypatch.setattr(recovery, "_authenticator_blocks", lambda _path: [ciphertext])

    secret = tmp_path / "epg-key.secret"
    status = tmp_path / "status.json"
    assert recovery.recover_numeric_key(
        tmp_path / "capture.pcap",
        secret,
        status,
        start=40,
        end=45,
        workers=1,
    ) is True
    assert recovery.LocalSecretStore(secret).get_epg_key() == key.decode("ascii")
    assert '"status": "found"' in status.read_text(encoding="utf-8")
