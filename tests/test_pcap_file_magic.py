"""Tests for classic pcap file-header magic acceptance.

The readers in ``services/stb_discovery_service.py`` sniff the 24-byte libpcap
file header and bail out on an unrecognised magic.  Two native-endian magics
exist: ``0xA1B2C3D4`` for microsecond timestamps and ``0xA1B23C4D`` for
nanosecond timestamps.  Only the former was accepted, so a capture written with
nanosecond resolution was silently discarded (empty dict) and the caller could
not tell that apart from "the capture contained no matching traffic".
"""
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.stb_discovery_service import _reassemble_tcp_streams  # noqa: E402

MAGIC_USEC = 0xA1B2C3D4
MAGIC_NSEC = 0xA1B23C4D

SRV = "10.7.10.132"
STB = "192.168.100.13"
SPORT = 80
DPORT = 54321
SEQ = 1000
PAYLOAD = b"payload-behind-magic-check"


def _eth_frame(src_ip, dst_ip, src_port, dst_port, seq, payload):
    tcp = struct.pack(
        ">HHIIBBHHH", src_port, dst_port, seq, 0, (5 << 4), 0x18, 8192, 0, 0
    )
    ip = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 1, 0, 64, 6, 0,
        bytes(int(o) for o in src_ip.split(".")), bytes(int(o) for o in dst_ip.split(".")),
    )
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    return eth + ip + tcp + payload


def _write_pcap_with_magic(magic: int, frames: list) -> str:
    """Write a little-endian classic pcap with the given file-header magic."""
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", magic, 2, 4, 0, 0, 65535, 1))
        for frame in frames:
            f.write(struct.pack("<IIII", 0, 0, len(frame), len(frame)))
            f.write(frame)
    return path


class TestPcapMagicAcceptance:
    def _assert_stream_present(self, magic: int):
        frame = _eth_frame(SRV, STB, SPORT, DPORT, SEQ, PAYLOAD)
        path = _write_pcap_with_magic(magic, [frame])
        try:
            streams = _reassemble_tcp_streams(path)
        finally:
            os.unlink(path)
        key = (SRV, SPORT, STB, DPORT)
        assert key in streams, (
            f"magic 0x{magic:08X} was rejected; 4-tuple missing from streams"
        )
        assert PAYLOAD in streams[key]

    def test_microsecond_magic_accepted(self):
        """0xA1B2C3D4 — microsecond resolution, the previously supported case."""
        self._assert_stream_present(MAGIC_USEC)

    def test_nanosecond_magic_accepted(self):
        """0xA1B23C4D — nanosecond resolution must parse identically to usec."""
        self._assert_stream_present(MAGIC_NSEC)

    def test_pcapng_still_rejected(self):
        """A pcapng file is not a classic pcap and must not be misread as one."""
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        with open(path, "wb") as f:
            f.write(b"\x0a\x0d\x0d\x0a" + b"\x1c\x00\x00\x00" + b"\x4d\x3c\x2b\x1a")
            f.write(b"\x01\x00\x00\x00" + b"\xff\xff\xff\xff" * 4)
        try:
            assert _reassemble_tcp_streams(path) == {}
        finally:
            os.unlink(path)
