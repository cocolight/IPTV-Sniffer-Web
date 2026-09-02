#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Minimal RTSP/UDP catch-up client for operator-specific MP2T SETUP.

Some IPTV platforms reject FFmpeg's separate UDP/TCP SETUP attempts.  Their
STB advertises four MP2T transport alternatives in one request and includes a
dynamic X-NAT_ADDRESS header.  This client reproduces that control flow and
returns the MPEG-TS payload carried by the selected RTP/UDP transport.
"""
from __future__ import annotations

import socket
from collections.abc import Iterator
from urllib.parse import urlsplit


class RtspCatchupError(RuntimeError):
    """User-safe RTSP failure category without retaining response contents."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


class CombinedRtspUdpSession:
    """Open one STB-compatible RTSP session and expose MPEG-TS chunks."""

    def __init__(self, url: str, user_agent: str = "", timeout_seconds: float = 12.0) -> None:
        self.url = self._validate_url(url)
        self.user_agent = self._clean_header(user_agent or "IPTV-Sniffer-Web")
        self.timeout_seconds = max(1.0, float(timeout_seconds))
        self.control: socket.socket | None = None
        self.rtp: socket.socket | None = None
        self.rtcp: socket.socket | None = None
        self.session_id = ""
        self.play_url = self.url
        self._buffer = b""
        self._cseq = 0

    @staticmethod
    def _clean_header(value: str) -> str:
        return str(value or "").replace("\r", " ").replace("\n", " ").strip()

    @staticmethod
    def _validate_url(url: str) -> str:
        value = str(url or "").strip()
        parsed = urlsplit(value)
        if parsed.scheme.lower() != "rtsp" or not parsed.hostname or "\r" in value or "\n" in value:
            raise RtspCatchupError("rtsp_url_invalid")
        return value

    @staticmethod
    def _build_transport(local_ip: str, client_port: int) -> str:
        alternatives = (
            f"MP2T/RTP/UDP;unicast;destination={local_ip};client_port={client_port}-{client_port + 1}",
            f"MP2T/RTP/TCP;unicast;destination={local_ip};interleaved=0-1",
            f"MP2T/UDP;unicast;destination={local_ip};client_port={client_port}-{client_port + 1}",
            f"MP2T/TCP;unicast;destination={local_ip};interleaved=0-1",
        )
        return ",".join(alternatives)

    @staticmethod
    def _rtp_payload(packet: bytes) -> bytes:
        if len(packet) < 12 or packet[0] >> 6 != 2:
            return b""
        offset = 12 + (packet[0] & 0x0F) * 4
        if packet[0] & 0x10:
            if len(packet) < offset + 4:
                return b""
            extension_words = int.from_bytes(packet[offset + 2 : offset + 4], "big")
            offset += 4 + extension_words * 4
        end = len(packet)
        if packet[0] & 0x20:
            padding = packet[-1]
            if not padding or padding > end - offset:
                return b""
            end -= padding
        return packet[offset:end] if end > offset else b""

    def _connect(self, url: str) -> socket.socket:
        parsed = urlsplit(url)
        try:
            sock = socket.create_connection(
                (parsed.hostname, parsed.port or 554), timeout=self.timeout_seconds,
            )
            sock.settimeout(self.timeout_seconds)
            return sock
        except socket.timeout as exc:
            raise RtspCatchupError("rtsp_timeout") from exc
        except OSError as exc:
            raise RtspCatchupError("rtsp_connection_failed") from exc

    def _send(self, method: str, url: str, headers: dict[str, str]) -> None:
        if self.control is None:
            raise RtspCatchupError("rtsp_connection_failed")
        self._cseq += 1
        lines = [f"{method} {self._validate_url(url)} RTSP/1.0", f"CSeq: {self._cseq}"]
        lines.extend(f"{name}: {self._clean_header(value)}" for name, value in headers.items())
        try:
            self.control.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        except (UnicodeEncodeError, OSError) as exc:
            raise RtspCatchupError("rtsp_connection_failed") from exc

    def _read_response(self) -> tuple[int, dict[str, str], bytes]:
        if self.control is None:
            raise RtspCatchupError("rtsp_connection_failed")
        try:
            while b"\r\n\r\n" not in self._buffer:
                if len(self._buffer) > 65536:
                    raise RtspCatchupError("rtsp_response_invalid")
                chunk = self.control.recv(65536)
                if not chunk:
                    raise RtspCatchupError("rtsp_connection_failed")
                self._buffer += chunk
            raw_headers, self._buffer = self._buffer.split(b"\r\n\r\n", 1)
            lines = raw_headers.decode("latin-1", errors="replace").split("\r\n")
            parts = lines[0].split()
            if len(parts) < 2 or not parts[1].isdigit():
                raise RtspCatchupError("rtsp_response_invalid")
            status = int(parts[1])
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    name, value = line.split(":", 1)
                    headers[name.strip().lower()] = value.strip()
            length = int(headers.get("content-length") or 0)
            if length < 0 or length > 2_000_000:
                raise RtspCatchupError("rtsp_response_invalid")
            while len(self._buffer) < length:
                chunk = self.control.recv(65536)
                if not chunk:
                    raise RtspCatchupError("rtsp_connection_failed")
                self._buffer += chunk
            body, self._buffer = self._buffer[:length], self._buffer[length:]
            return status, headers, body
        except socket.timeout as exc:
            raise RtspCatchupError("rtsp_timeout") from exc
        except ValueError as exc:
            raise RtspCatchupError("rtsp_response_invalid") from exc

    @staticmethod
    def _status_category(status: int) -> str:
        if status == 401:
            return "rtsp_unauthorized"
        if status == 403:
            return "rtsp_forbidden"
        if status == 461:
            return "rtsp_transport_unsupported"
        return "rtsp_status_error"

    @staticmethod
    def _redirect_url(current_url: str, location: str) -> str:
        value = str(location or "").strip()
        if value.startswith("rtsp://"):
            return CombinedRtspUdpSession._validate_url(value)
        parsed = urlsplit(current_url)
        if value.startswith("/"):
            return CombinedRtspUdpSession._validate_url(f"rtsp://{parsed.netloc}{value}")
        root = current_url.rsplit("/", 1)[0] + "/"
        return CombinedRtspUdpSession._validate_url(root + value)

    @staticmethod
    def _setup_url(play_url: str, content_base: str, sdp: bytes) -> str:
        controls = []
        for line in sdp.decode("utf-8", errors="replace").splitlines():
            if line.startswith("a=control:"):
                value = line.split(":", 1)[1].strip()
                if value and value != "*":
                    controls.append(value)
        if not controls:
            return CombinedRtspUdpSession._validate_url(content_base or play_url)
        control = controls[-1]
        if control.startswith("rtsp://"):
            return CombinedRtspUdpSession._validate_url(control)
        parsed = urlsplit(play_url)
        if control.startswith("/"):
            return CombinedRtspUdpSession._validate_url(f"rtsp://{parsed.netloc}{control}")
        root = (content_base or play_url).split("?", 1)[0]
        if not root.endswith("/"):
            root += "/"
        return CombinedRtspUdpSession._validate_url(root + control)

    @staticmethod
    def _bind_udp_pair(local_ip: str) -> tuple[socket.socket, socket.socket, int]:
        for _ in range(100):
            rtp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rtp.bind((local_ip, 0))
            port = int(rtp.getsockname()[1])
            if port % 2:
                rtp.close()
                continue
            rtcp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                rtcp.bind((local_ip, port + 1))
                return rtp, rtcp, port
            except OSError:
                rtp.close()
                rtcp.close()
        raise RtspCatchupError("rtsp_udp_bind_failed")

    def open(self) -> bytes:
        """Complete DESCRIBE/SETUP/PLAY and return the first MPEG-TS chunk."""
        current_url = self.url
        try:
            for redirects in range(4):
                self.control = self._connect(current_url)
                self._buffer = b""
                self._cseq = 0
                self._send("DESCRIBE", current_url, {
                    "Accept": "application/sdp", "User-Agent": self.user_agent,
                })
                status, headers, sdp = self._read_response()
                if status in {301, 302, 303, 307, 308}:
                    location = headers.get("location", "")
                    if not location or redirects >= 3:
                        raise RtspCatchupError("rtsp_redirect_invalid")
                    current_url = self._redirect_url(current_url, location)
                    self.control.close()
                    self.control = None
                    continue
                if status != 200:
                    raise RtspCatchupError(self._status_category(status))
                break
            else:
                raise RtspCatchupError("rtsp_redirect_invalid")

            self.play_url = current_url
            local_ip, local_control_port = self.control.getsockname()[:2]
            self.rtp, self.rtcp, client_port = self._bind_udp_pair(str(local_ip))
            self.rtp.settimeout(self.timeout_seconds)
            setup_url = self._setup_url(current_url, headers.get("content-base", ""), sdp)
            self._send("SETUP", setup_url, {
                "Transport": self._build_transport(str(local_ip), client_port),
                "User-Agent": self.user_agent,
                "X-NAT_ADDRESS": f"{local_ip}:{local_control_port}",
            })
            status, headers, _ = self._read_response()
            if status != 200:
                raise RtspCatchupError(self._status_category(status))
            selected_transport = headers.get("transport", "").lower()
            if "client_port=" not in selected_transport:
                raise RtspCatchupError("rtsp_transport_unsupported")
            self.session_id = headers.get("session", "").split(";", 1)[0].strip()
            if not self.session_id:
                raise RtspCatchupError("rtsp_response_invalid")
            self._send("PLAY", current_url, {
                "Session": self.session_id,
                "Range": "npt=0.000-",
                "User-Agent": self.user_agent,
            })
            status, _, _ = self._read_response()
            if status != 200:
                raise RtspCatchupError(self._status_category(status))
            return self.read_payload()
        except RtspCatchupError:
            self.close()
            raise
        except socket.timeout as exc:
            self.close()
            raise RtspCatchupError("rtsp_timeout") from exc
        except OSError as exc:
            self.close()
            raise RtspCatchupError("rtsp_connection_failed") from exc

    def read_payload(self) -> bytes:
        if self.rtp is None:
            raise RtspCatchupError("rtsp_connection_failed")
        for _ in range(100):
            try:
                packet, _ = self.rtp.recvfrom(65536)
            except socket.timeout as exc:
                raise RtspCatchupError("rtsp_timeout") from exc
            if packet and packet[0] == 0x47:
                return packet
            payload = self._rtp_payload(packet)
            if payload:
                return payload
        raise RtspCatchupError("rtsp_no_media")

    def iter_payloads(self, first_payload: bytes) -> Iterator[bytes]:
        try:
            yield first_payload
            while True:
                yield self.read_payload()
        except RtspCatchupError:
            return
        finally:
            self.close()

    def close(self) -> None:
        if self.control is not None and self.session_id:
            try:
                self._send("TEARDOWN", self.play_url, {
                    "Session": self.session_id, "User-Agent": self.user_agent,
                })
            except Exception:
                pass
        for sock in (self.rtp, self.rtcp, self.control):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self.rtp = self.rtcp = self.control = None
