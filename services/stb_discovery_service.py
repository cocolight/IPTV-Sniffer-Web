#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""STB boot capture and channel list discovery via tcpdump + TCP stream reassembly."""
from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

from services.log_service import AppLogger


def _parse_ip(data: bytes, off: int) -> str:
    return ".".join(str(b) for b in data[off : off + 4])


_MAC_PLAIN = re.compile(r"^[0-9a-fA-F]{12}$")
_MAC_COLON = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
_MAC_DASH = re.compile(r"^[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}$")
_MAC_CISCO = re.compile(r"^[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}$")


def normalize_mac(value: str | None) -> str:
    """把常见 MAC 写法统一成小写冒号分隔；空值返回空串。

    接受 `aa:bb:cc:dd:ee:ff`、`aa-bb-cc-dd-ee-ff` 与 Cisco 风格 `aabb.ccdd.eeff`。
    格式非法时抛 ValueError，避免把 tcpdump 语法错误的表达式交给它——
    那会让 tcpdump 启动即退出，而旧实现不会报告任何原因。
    """
    text = str(value or "").strip()
    if not text:
        return ""
    lowered = text.lower()
    if _MAC_COLON.match(lowered):
        return lowered
    if _MAC_DASH.match(lowered):
        return lowered.replace("-", ":")
    if _MAC_CISCO.match(lowered):
        compact = lowered.replace(".", "")
        return ":".join(compact[i : i + 2] for i in range(0, 12, 2))
    if _MAC_PLAIN.match(lowered):
        return ":".join(lowered[i : i + 2] for i in range(0, 12, 2))
    raise ValueError(
        f"MAC 地址格式无效：{value!r}（示例：48:57:02:25:bb:e3、48-57-02-25-bb-e3 或 4857.0225.bbe3）"
    )


# ── DHCP helpers ─────────────────────────────────────────────────────────────

def _parse_dhcp_options(options_bytes: bytes) -> dict[int, bytes]:
    """Parse DHCP options TLV into {code: value_bytes}."""
    opts: dict[int, bytes] = {}
    i = 0
    while i < len(options_bytes):
        code = options_bytes[i]
        i += 1
        if code == 0:   # PAD
            continue
        if code == 255:  # END
            break
        if i >= len(options_bytes):
            break
        length = options_bytes[i]
        i += 1
        if i + length > len(options_bytes):
            break
        opts[code] = options_bytes[i : i + length]
        i += length
    return opts


def _parse_opt125(data: bytes) -> str:
    """Parse DHCP Option 125 (Vendor-Identifying Vendor-Specific)."""
    _ENTERPRISE_NAMES = {2011: "中兴ZTE", 3561: "Broadcom/TR-069", 4491: "CableLabs"}
    parts: list[str] = []
    i = 0
    while i + 5 <= len(data):
        enterprise = struct.unpack(">I", data[i : i + 4])[0]
        data_len = data[i + 4]
        i += 5
        if i + data_len > len(data):
            break
        sub_data = data[i : i + data_len]
        i += data_len
        sub_parts: list[str] = []
        j = 0
        while j + 2 <= len(sub_data):
            sub_code = sub_data[j]
            sub_len = sub_data[j + 1]
            j += 2
            if j + sub_len > len(sub_data):
                break
            raw = sub_data[j : j + sub_len]
            j += sub_len
            try:
                sv = raw.decode("utf-8", errors="replace").strip("\x00").strip()
                if not all(c.isprintable() or c in "\t\n" for c in sv):
                    sv = raw.hex()
            except Exception:
                sv = raw.hex()
            sub_parts.append(f"sub{sub_code}={sv}")
        label = _ENTERPRISE_NAMES.get(enterprise, str(enterprise))
        parts.append(f"Enterprise({label}): " + "; ".join(sub_parts))
    return "\n".join(parts)


def _parse_dhcp_packet(payload: bytes) -> dict[str, Any] | None:
    """Parse a DHCP packet from UDP payload. Returns None if not valid DHCP."""
    if len(payload) < 240:
        return None
    if payload[236:240] != b"\x63\x82\x53\x63":  # magic cookie
        return None
    op = payload[0]
    hlen = min(payload[2], 16)
    xid = struct.unpack(">I", payload[4:8])[0]
    yiaddr = _parse_ip(payload, 16)
    mac = ":".join(f"{b:02x}" for b in payload[28 : 28 + hlen]) if hlen >= 6 else ""
    options = _parse_dhcp_options(payload[240:])
    msg_type = options.get(53, b"\x00")[0] if 53 in options else 0
    return {"op": op, "xid": xid, "yiaddr": yiaddr, "mac": mac,
            "msg_type": msg_type, "options": options}


def _extract_dhcp_from_pcap(pcap_path: str) -> dict[str, Any]:
    """Extract STB DHCP auth info from a pcap file."""
    _VLAN_ETYPES = {0x8100, 0x88A8, 0x9100}
    _DLT_LINUX_SLL = 113
    _DLT_LINUX_SLL2 = 276
    requests: dict[int, dict] = {}
    responses: dict[int, dict] = {}
    with open(pcap_path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return {}
        magic = struct.unpack("<I", header[:4])[0]
        if magic not in (0xA1B2C3D4, 0xD3B4A1B2):
            return {}
        linktype = struct.unpack("<I", header[20:24])[0]
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            inc_len = struct.unpack("<I", hdr[8:12])[0]
            pkt = f.read(inc_len)
            if linktype == _DLT_LINUX_SLL:
                if len(pkt) < 16:
                    continue
                if struct.unpack(">H", pkt[14:16])[0] != 0x0800:
                    continue
                ip_start = 16
            elif linktype == _DLT_LINUX_SLL2:
                if len(pkt) < 20:
                    continue
                if struct.unpack(">H", pkt[0:2])[0] != 0x0800:
                    continue
                ip_start = 20
            else:
                if len(pkt) < 14:
                    continue
                p = 12
                if p + 2 > len(pkt):
                    continue
                etype = struct.unpack(">H", pkt[p : p + 2])[0]
                while etype in _VLAN_ETYPES:
                    p += 4
                    if p + 2 > len(pkt):
                        break
                    etype = struct.unpack(">H", pkt[p : p + 2])[0]
                if etype != 0x0800:
                    continue
                ip_start = p + 2
            if ip_start + 20 > len(pkt):
                continue
            if pkt[ip_start + 9] != 17:  # not UDP
                continue
            ip_ihl = (pkt[ip_start] & 0x0F) * 4
            udp_off = ip_start + ip_ihl
            if udp_off + 8 > len(pkt):
                continue
            src_port = struct.unpack(">H", pkt[udp_off : udp_off + 2])[0]
            dst_port = struct.unpack(">H", pkt[udp_off + 2 : udp_off + 4])[0]
            if src_port not in (67, 68) and dst_port not in (67, 68):
                continue
            parsed = _parse_dhcp_packet(pkt[udp_off + 8:])
            if not parsed:
                continue
            xid = parsed["xid"]
            if parsed["op"] == 1:
                requests.setdefault(xid, parsed)
            elif parsed["op"] == 2:
                responses.setdefault(xid, parsed)

    # Pick best matched request+response pair
    best_req, best_resp = None, None
    for xid, req in requests.items():
        if xid in responses:
            best_req, best_resp = req, responses[xid]
            break
    if best_req is None and requests:
        best_req = next(iter(requests.values()))
    if best_req is None:
        return {}

    opts_req = best_req["options"]
    opts_resp = best_resp["options"] if best_resp else {}

    def _str(opts: dict, code: int) -> str:
        val = opts.get(code)
        if not val:
            return ""
        try:
            s = val.decode("utf-8", errors="replace").strip("\x00").strip()
            return s if all(c.isprintable() or c in " \t" for c in s) else val.hex()
        except Exception:
            return val.hex()

    def _ip(opts: dict, code: int) -> str:
        val = opts.get(code)
        return ".".join(str(b) for b in val[:4]) if val and len(val) >= 4 else ""

    def _ips(opts: dict, code: int) -> list[str]:
        val = opts.get(code)
        if not val:
            return []
        return [".".join(str(b) for b in val[i : i + 4])
                for i in range(0, len(val) - 3, 4)]

    raw61 = opts_req.get(61, b"")
    if raw61 and raw61[0] == 1 and len(raw61) == 7:
        client_id = "01:" + ":".join(f"{b:02x}" for b in raw61[1:])
    elif raw61:
        client_id = raw61.hex()
    else:
        client_id = ""

    assigned_ip = ""
    if best_resp:
        yi = best_resp.get("yiaddr", "")
        if yi and yi != "0.0.0.0":
            assigned_ip = yi

    return {
        "mac": best_req.get("mac", ""),
        "assigned_ip": assigned_ip,
        "gateway": _ip(opts_resp, 3),
        "netmask": _ip(opts_resp, 1),
        "dns": _ips(opts_resp, 6),
        "dhcp_server": _ip(opts_resp, 54),
        "vendor_class": opts_req[60].hex() if 60 in opts_req else "",
        "hostname": _str(opts_req, 12),
        "client_id": client_id,
        "vendor_specific_125": _parse_opt125(opts_req[125]) if 125 in opts_req else "",
        "vendor_specific_125_raw": opts_req[125].hex() if 125 in opts_req else "",
    }


def _unchunk(data: bytes) -> bytes:
    """Strip HTTP chunked transfer encoding."""
    out = bytearray()
    i = 0
    while i < len(data):
        nl = data.find(b"\r\n", i)
        if nl == -1:
            break
        try:
            size = int(data[i:nl], 16)
        except ValueError:
            break
        if size == 0:
            break
        out.extend(data[nl + 2 : nl + 2 + size])
        i = nl + 2 + size + 2
    return bytes(out)


def _split_http_responses(raw: bytes) -> list[tuple[str, bytes]]:
    """Split a TCP stream into individual (headers, body) HTTP response pairs."""
    responses: list[tuple[str, bytes]] = []
    i = 0
    while i < len(raw):
        if not raw[i : i + 5].startswith(b"HTTP/"):
            i += 1
            continue
        hdr_end = raw.find(b"\r\n\r\n", i)
        if hdr_end == -1:
            break
        headers_str = raw[i:hdr_end].decode("utf-8", errors="replace")
        body_start = hdr_end + 4
        cl_match = re.search(r"[Cc]ontent-[Ll]ength:\s*(\d+)", headers_str)
        te_match = re.search(r"[Tt]ransfer-[Ee]ncoding:\s*chunked", headers_str, re.IGNORECASE)
        if cl_match:
            body_len = int(cl_match.group(1))
            body = raw[body_start : body_start + body_len]
            next_i = body_start + body_len
        elif te_match:
            body_raw = raw[body_start:]
            body = _unchunk(body_raw)
            chunk_end = body_raw.find(b"\r\n0\r\n")
            next_i = body_start + chunk_end + 7 if chunk_end != -1 else len(raw)
        else:
            body = b""
            next_i = body_start
        is_gzip = "content-encoding: gzip" in headers_str.lower()
        if is_gzip and len(body) > 10:
            try:
                body = gzip.decompress(body)
            except Exception:
                pass
        responses.append((headers_str, body))
        i = next_i
    return responses


def _iter_http_requests(raw: bytes) -> list[tuple[str, str, bytes, list[str], list[str]]]:
    """Return complete HTTP requests with only cookie *names* as metadata.

    The raw request is deliberately returned as bytes so it can be preserved
    in the private STB evidence archive.  Callers must never place it in an
    API response, log line, or global JSON backup because forms may contain
    Authenticator, UserToken, and passwords.
    """
    found: list[tuple[str, str, bytes, list[str], list[str]]] = []
    cursor = 0
    request_re = re.compile(br"(?:GET|POST)\s+([^\s]+)\s+HTTP/[0-9.]+\r\n")
    while cursor < len(raw):
        match = request_re.search(raw, cursor)
        if not match:
            break
        start = match.start()
        header_end = raw.find(b"\r\n\r\n", start)
        if header_end < 0:
            break
        header_text = raw[start:header_end].decode("latin1", errors="replace")
        lines = header_text.split("\r\n")
        first = lines[0].split()
        method = first[0] if first else ""
        path = first[1] if len(first) > 1 else ""
        content_length = 0
        cookie_names: list[str] = []
        header_names: list[str] = []
        for line in lines[1:]:
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            name = name.strip().lower()
            header_names.append(name)
            if name == "content-length":
                try:
                    content_length = max(0, int(value.strip()))
                except ValueError:
                    content_length = 0
            elif name == "cookie":
                cookie_names.extend(
                    item.split("=", 1)[0].strip()
                    for item in value.split(";") if "=" in item
                )
        end = header_end + 4 + content_length
        if end > len(raw):
            cursor = header_end + 4
            continue
        found.append((method, path, raw[start:end], sorted(set(cookie_names)), header_names))
        cursor = end
    return found


def _response_cookie_names(raw: bytes) -> list[str]:
    """Extract only cookie names from a raw server stream for safe manifests."""
    names: list[str] = []
    for headers, _body in _split_http_responses(raw):
        for line in headers.split("\r\n")[1:]:
            if line.lower().startswith("set-cookie:") and "=" in line:
                names.append(line.split(":", 1)[1].strip().split("=", 1)[0])
    return sorted(set(name for name in names if name))


def _reassemble_tcp_streams(pcap_path: str) -> dict[tuple[str, int, str, int], bytes]:
    """Read a pcap file and reassemble TCP payload streams by 4-tuple key.

    Handles Ethernet (DLT=1), Linux cooked SLL (DLT=113), and SLL2 (DLT=276)
    link types so captures on the ``any`` interface work correctly.  Also
    handles 802.1Q / QinQ VLAN tags on Ethernet frames.  Packets are sorted by
    TCP sequence number and retransmissions are deduplicated.
    """
    _VLAN_ETYPES = {0x8100, 0x88A8, 0x9100}
    _DLT_LINUX_SLL = 113
    _DLT_LINUX_SLL2 = 276
    stream_seqs: dict[tuple[str, int, str, int], dict[int, bytes]] = {}
    with open(pcap_path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return {}
        magic = struct.unpack("<I", header[:4])[0]
        if magic not in (0xA1B2C3D4, 0xD3B4A1B2):
            return {}
        linktype = struct.unpack("<I", header[20:24])[0]
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            inc_len = struct.unpack("<I", hdr[8:12])[0]
            pkt = f.read(inc_len)
            if linktype == _DLT_LINUX_SLL:
                # SLL v1: 16-byte cooked header; EtherType at bytes 14-15
                if len(pkt) < 16:
                    continue
                if struct.unpack(">H", pkt[14:16])[0] != 0x0800:
                    continue
                ip_start = 16
            elif linktype == _DLT_LINUX_SLL2:
                # SLL v2: 20-byte cooked header; EtherType at bytes 0-1
                if len(pkt) < 20:
                    continue
                if struct.unpack(">H", pkt[0:2])[0] != 0x0800:
                    continue
                ip_start = 20
            else:
                # Ethernet (DLT=1) — walk past 802.1Q / QinQ VLAN tags
                if len(pkt) < 14:
                    continue
                p = 12
                if p + 2 > len(pkt):
                    continue
                etype = struct.unpack(">H", pkt[p : p + 2])[0]
                while etype in _VLAN_ETYPES:
                    p += 4
                    if p + 2 > len(pkt):
                        break
                    etype = struct.unpack(">H", pkt[p : p + 2])[0]
                if etype != 0x0800:
                    continue
                ip_start = p + 2
            if ip_start + 20 > len(pkt):
                continue
            if pkt[ip_start + 9] != 6:
                continue  # not TCP
            ip_ihl = (pkt[ip_start] & 0x0F) * 4
            src_ip = _parse_ip(pkt, ip_start + 12)
            dst_ip = _parse_ip(pkt, ip_start + 16)
            tcp_off = ip_start + ip_ihl
            if tcp_off + 20 > len(pkt):
                continue
            src_port = struct.unpack(">H", pkt[tcp_off : tcp_off + 2])[0]
            dst_port = struct.unpack(">H", pkt[tcp_off + 2 : tcp_off + 4])[0]
            seq = struct.unpack(">I", pkt[tcp_off + 4 : tcp_off + 8])[0]
            data_off = tcp_off + ((pkt[tcp_off + 12] >> 4) * 4)
            payload = pkt[data_off:]
            if not payload:
                continue
            key = (src_ip, src_port, dst_ip, dst_port)
            seqs = stream_seqs.setdefault(key, {})
            # A partial retransmission can arrive before the full segment.
            # Keep the longest payload for a sequence number; keeping the
            # first packet caused form fields (STBID/STBType/STBVersion) to
            # disappear from otherwise complete boot captures.
            if seq not in seqs or len(payload) > len(seqs[seq]):
                seqs[seq] = payload
    streams: dict[tuple[str, int, str, int], bytes] = {}
    for key, seq_map in stream_seqs.items():
        merged = bytearray()
        next_seq: int | None = None
        for seq, payload in sorted(seq_map.items()):
            if next_seq is None:
                merged.extend(payload)
                next_seq = seq + len(payload)
                continue
            if seq >= next_seq:
                # Preserve a capture gap rather than inventing bytes.  Later
                # HTTP parsing can still use the complete following segment.
                merged.extend(payload)
                next_seq = seq + len(payload)
                continue
            overlap = next_seq - seq
            if overlap < len(payload):
                merged.extend(payload[overlap:])
                next_seq = seq + len(payload)
        streams[key] = bytes(merged)
    return streams


def _parse_chanlist_html(html: bytes) -> list[dict[str, Any]]:
    """Parse CTC/CU middleware Channel config calls into channel dicts."""
    text = _decode_payload_text(html)
    call_re = re.compile(
        r"""(?:(?:Authentication\.)?(?:CUSetConfig|CTCSetConfig)|jsSetConfig)\s*\(
            \s*(?P<key_quote>['"])Channel(?P=key_quote)\s*,
            \s*(?P<value_quote>['"])(?P<value>.*?)(?P=value_quote)\s*\)
        """,
        re.DOTALL | re.VERBOSE,
    )
    blocks = [match.group("value") for match in call_re.finditer(text)]
    channels: list[dict[str, Any]] = []
    for block in blocks:
        raw = re.findall(r"""(\w+)=(?:"([^"]*)"|'([^']*)')""", block)
        pairs = {k: (dq or sq) for k, dq, sq in raw}
        chan_name = pairs.get("ChannelName", "").strip()
        user_chan_id = pairs.get("UserChannelID", "")
        channel_url = pairs.get("ChannelURL", "")
        chan_id = pairs.get("ChannelID", "")
        is_hd = pairs.get("IsHDChannel", "0") == "2"
        time_shift = pairs.get("TimeShift", "0") == "1"
        time_shift_minutes_s = pairs.get("TimeShiftLength", "")
        fcc_ip = pairs.get("ChannelFCCIP", "").strip()
        fcc_port_s = pairs.get("ChannelFCCPort", "")
        fcc_addr = (
            pairs.get("ChannelFCCServerAddr") or pairs.get("ChannelFccAgentAddr") or
            pairs.get("ChannelFCCAddr") or ""
        ).strip()
        if fcc_addr:
            addr_host, sep, addr_port = fcc_addr.rpartition(":")
            if sep and addr_host:
                fcc_ip = fcc_ip or addr_host.strip()
                fcc_port_s = fcc_port_s or addr_port.strip()
            elif not fcc_ip:
                fcc_ip = fcc_addr
        fec_port_s = pairs.get("ChannelFECPort", "")
        group_name = (
            pairs.get("GroupName") or pairs.get("ChannelGroupName") or pairs.get("ChannelGroup") or
            pairs.get("CategoryName") or pairs.get("Category") or pairs.get("ChannelTypeName") or ""
        ).strip()
        backtv_url = (
            pairs.get("TimeShiftURL") or pairs.get("BacktimeURL") or
            pairs.get("BackUrl") or pairs.get("TimeshiftUrl") or
            pairs.get("startOverUrl") or ""
        ).strip()
        m = re.match(r"(?:igmp|udp|rtp)://([0-9.]+):(\d+)", channel_url, re.IGNORECASE)
        if not m:
            m = re.search(
                r"(?:igmp|udp|rtp)://([0-9.]+):(\d+)",
                pairs.get("ChannelSDP", ""),
                re.IGNORECASE,
            )
        ip, port = (m.group(1), int(m.group(2))) if m else ("", 0)
        if not ip or not port or not chan_name:
            continue
        channels.append(
            {
                "num": int(user_chan_id) if user_chan_id.isdigit() else 0,
                "name": chan_name,
                "category": _channel_category_from_group(group_name, chan_name),
                "operator_group": _clean_group_name(group_name),
                "ip": ip,
                "port": port,
                "channel_id": chan_id,
                "is_hd": is_hd,
                "time_shift": time_shift,
                "time_shift_minutes": int(time_shift_minutes_s) if time_shift_minutes_s.isdigit() else None,
                "fcc_ip": fcc_ip,
                "fcc_port": int(fcc_port_s) if fcc_port_s.isdigit() else None,
                "fec_port": int(fec_port_s) if fec_port_s.isdigit() else None,
                "backtv_url": backtv_url,
            }
        )
    channels.sort(key=lambda x: x["num"])
    return channels


_NANJING_COLUMN_GROUPS = {
    "0204": ("央视频道", "CCTV"),
    "0205": ("江苏频道", "江苏"),
    "0206": ("其它频道", "其它"),
    "0207": ("卫视频道", "卫视"),
    "020B": ("广播频道", "广播"),
}


def _extract_json_object(text: str, start: int) -> dict[str, Any] | None:
    """Decode one JSON object starting at or after *start* using brace counting."""
    start = text.find("{", start)
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    value = json.loads(text[start:index + 1])
                except (TypeError, ValueError):
                    return None
                return value if isinstance(value, dict) else None
    return None


def _parse_pc_channel_catalog(body: bytes) -> dict[str, dict[str, str]]:
    """Parse Jiangsu Telecom PC_ChannelList metadata used by its EPG player."""
    text = _decode_payload_text(body)
    marker = re.search(r"packageData\s*\(\s*['\"]PC_ChannelList['\"]\s*,", text)
    if not marker:
        return {}
    payload = _extract_json_object(text, marker.end())
    if not payload:
        return {}
    catalog: dict[str, dict[str, str]] = {}
    for item in payload.get("channelAllList") or []:
        if not isinstance(item, dict):
            continue
        channel_id = str(item.get("channelcode") or "").strip()
        if not channel_id:
            continue
        column_code = str(item.get("columncode") or "").strip().upper()
        category, operator_group = _NANJING_COLUMN_GROUPS.get(column_code, ("", ""))
        catalog[channel_id] = {
            "name": str(item.get("channelname") or "").strip(),
            "category": category,
            "operator_group": operator_group,
            "mixno": str(item.get("mixno") or "").strip(),
        }
    return catalog


def _parse_vsp_json(body: bytes) -> list[dict[str, Any]]:
    """Parse /VSP/V3/QueryChannelListBySubject JSON response."""
    channels: list[dict[str, Any]] = []
    try:
        data = json.loads(body)
    except Exception:
        return channels
    for ch in data.get("channelDetails") or []:
        if not isinstance(ch, dict):
            continue
        name = str(ch.get("name", "")).strip()
        chan_no = ch.get("channelNO", "")
        chan_id = str(ch.get("ID", "")).strip()
        group_name = str(ch.get("groupName") or ch.get("subjectName") or ch.get("categoryName") or "").strip()
        if not name:
            continue
        # Extract multicast URL from physicalChannels
        for pc in ch.get("physicalChannels") or []:
            if not isinstance(pc, dict):
                continue
            btv = pc.get("btvCR") or {}
            if isinstance(btv, dict):
                url = str(btv.get("mediaURL", "") or btv.get("broadcastURL", "")).strip()
                m = re.match(r"(?:igmp|udp|rtp)://([0-9.]+):(\d+)", url)
                if m:
                    channels.append(
                        {
                            "num": int(chan_no) if str(chan_no).isdigit() else 0,
                            "name": name,
                            "category": _channel_category_from_group(group_name, name),
                            "operator_group": _clean_group_name(group_name),
                            "ip": m.group(1),
                            "port": int(m.group(2)),
                            "channel_id": chan_id,
                            "is_hd": False,
                            "time_shift": False,
                            "fcc_ip": "",
                            "fcc_port": None,
                            "fec_port": None,
                        }
                    )
    return channels


def _decode_payload_text(body: bytes) -> str:
    """Decode STB HTTP payloads that may be UTF-8 or GB18030."""
    for encoding in ("utf-8", "gb18030"):
        try:
            return body.decode(encoding)
        except UnicodeDecodeError:
            continue
    return body.decode("utf-8", errors="replace")


def _safe_int(value: Any) -> int | None:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if 0 <= number <= 65535 else None


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in {"1", "2", "true", "yes", "y", "on", "enable", "enabled"}


def _first_text(obj: dict[str, Any], *keys: str) -> str:
    lowered = {str(k).lower(): v for k, v in obj.items()}
    for key in keys:
        val = lowered.get(key.lower())
        if val not in (None, ""):
            return str(val).strip()
    return ""


def _first_int(obj: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = _first_text(obj, key)
        number = _safe_int(value)
        if number is not None:
            return number
    return None


def _clean_group_name(value: str) -> str:
    group = re.sub(r"[\x00-\x1f\x7f]+", "", str(value or "")).strip()
    group = re.sub(r"\s+", " ", group).strip(" ,;，；/\\")
    return group[:40]


def _channel_category_from_group(group: str, name: str) -> str:
    raw = _clean_group_name(group)
    if raw:
        upper = raw.upper()
        if "CCTV" in upper or "央视" in raw or "中央" in raw:
            return "央视频道"
        if "卫视" in raw:
            return "卫视频道"
        if raw in {"央视频道", "卫视频道", "其它频道"}:
            return raw
        return raw
    return "其它频道" if not name else _fallback_classify_channel_name(name)


def _fallback_classify_channel_name(name: str) -> str:
    normalized = str(name or "").strip().upper()
    if not normalized:
        return "其它频道"
    if "CCTV" in normalized or "央视" in name or "中央" in name:
        return "央视频道"
    if "卫视" in name:
        return "卫视频道"
    return "其它频道"


def _parse_multicast_url(url: str) -> tuple[str, int]:
    match = re.search(r"(?:igmp|udp|rtp)://([0-9.]+):(\d+)", str(url or ""), re.IGNORECASE)
    return (match.group(1), int(match.group(2))) if match else ("", 0)


def _parse_stream_params(ch: dict[str, Any]) -> tuple[str, int | None, int | None]:
    """Extract FCC/FEC params from direct fields, query strings, or SDP snippets."""
    fcc_ip = _first_text(ch, "channelFCCIP", "ChannelFCCIP", "fccIP", "fcc_ip")
    fcc_port = _first_int(ch, "channelFCCPort", "ChannelFCCPort", "fccPort", "fcc_port")
    fec_port = _first_int(ch, "channelFECPort", "ChannelFECPort", "fecPort", "fec_port")
    raw_parts = [
        _first_text(ch, "channelURL", "ChannelURL", "url", "mediaURL", "broadcastURL"),
        _first_text(ch, "channelSDP", "ChannelSDP", "sdp"),
    ]
    for raw in raw_parts:
        if not raw:
            continue
        parsed = urllib.parse.urlparse(raw)
        query = urllib.parse.parse_qs(parsed.query)
        if not fcc_ip:
            fcc_val = (query.get("fcc") or [""])[0]
            if ":" in fcc_val:
                fcc_ip = fcc_val.split(":", 1)[0].strip()
                if fcc_port is None:
                    fcc_port = _safe_int(fcc_val.split(":", 1)[1])
            else:
                fcc_ip = (query.get("ChannelFCCIP") or query.get("fcc_ip") or [""])[0].strip()
        if fcc_port is None:
            fcc_port = _safe_int((query.get("ChannelFCCPort") or query.get("fcc_port") or [""])[0])
        if fec_port is None:
            fec_port = _safe_int((query.get("fec") or query.get("ChannelFECPort") or query.get("fec_port") or [""])[0])
        if not fcc_ip:
            m = re.search(r"(?:ChannelFCCIP|fcc[_-]?ip)\s*[=:]\s*([0-9.]+)", raw, re.IGNORECASE)
            if m:
                fcc_ip = m.group(1)
        if fcc_port is None:
            m = re.search(r"(?:ChannelFCCPort|fcc[_-]?port)\s*[=:]\s*(\d{1,5})", raw, re.IGNORECASE)
            if m:
                fcc_port = _safe_int(m.group(1))
        if fec_port is None:
            m = re.search(r"(?:ChannelFECPort|fec[_-]?port)\s*[=:]\s*(\d{1,5})", raw, re.IGNORECASE)
            if m:
                fec_port = _safe_int(m.group(1))
    return fcc_ip, fcc_port, fec_port


def _iter_channel_dicts(data: Any):
    """Yield likely channel entries from regional JSON payloads."""
    if isinstance(data, dict):
        for key in (
            "channleInfoStruct",  # Beijing Unicom / Hisense IP811N typo
            "channelInfoStruct",
            "channelDetails",
            "channelList",
            "channels",
            "ChannelList",
        ):
            value = data.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        yield item
        for value in data.values():
            if isinstance(value, (dict, list)):
                yield from _iter_channel_dicts(value)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                if any(k.lower() in {"channelurl", "channelname", "channelid", "userchannelid"} for k in item):
                    yield item
                else:
                    yield from _iter_channel_dicts(item)
            elif isinstance(item, list):
                yield from _iter_channel_dicts(item)


def _extract_channel_objects_from_partial_json(text: str) -> list[dict[str, Any]]:
    """Extract individual channel JSON objects from truncated or malformed JSON.

    Used when the HTTP response headers and the opening of the JSON array are
    missing (e.g. the first N TCP segments were not captured).  Uses brace
    counting so each top-level ``{\u2026}`` object is extracted and parsed
    independently; objects that look like channel entries are returned.
    """
    result: list[dict[str, Any]] = []
    depth = 0
    start = -1
    for i, c in enumerate(text):
        if c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    obj_text = text[start : i + 1]
                    try:
                        obj = json.loads(obj_text)
                    except Exception:
                        start = -1
                        continue
                    if isinstance(obj, dict) and any(
                        k.lower() in {
                            "channelurl", "channelname", "channelid", "userchannelid"
                        }
                        for k in obj
                    ):
                        result.append(obj)
                    start = -1
    return result


def _parse_channel_acquire_json(body: bytes) -> list[dict[str, Any]]:
    """Parse Beijing Unicom /bj_stb/V1/STB/channelAcquire channel list JSON."""
    text = _decode_payload_text(body).lstrip("\ufeff").strip()
    # Strip HTTP chunked transfer-encoding size lines embedded in body fragments
    # (e.g. "\r\n2000\r\n" appearing mid-string when first TCP segments are missing).
    text = re.sub(r"\r\n[0-9a-fA-F]{1,8}\r\n", "", text)
    if not text or "channel" not in text.lower():
        return []

    data: Any = None
    try:
        data = json.loads(text)
    except Exception:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start : end + 1])
            except Exception:
                pass

    if data is None:
        # Last resort: brace-counted per-object extraction for partially captured
        # responses where the JSON array opening is in the missing TCP segments.
        channel_list = _extract_channel_objects_from_partial_json(text)
        if not channel_list:
            return []
        data = channel_list  # treat as a flat list of channel dicts

    channels: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ch in _iter_channel_dicts(data):
        name = _first_text(ch, "channelName", "ChannelName", "name", "Name")
        channel_url = _first_text(ch, "channelURL", "ChannelURL", "url", "mediaURL", "broadcastURL")
        ip, port = _parse_multicast_url(channel_url)
        if not ip or not port:
            ip, port = _parse_multicast_url(_first_text(ch, "channelSDP", "ChannelSDP", "sdp"))
        if not ip or not port or not name:
            continue
        key = f"{ip}:{port}"
        if key in seen:
            continue
        seen.add(key)
        user_chan_id = _first_text(ch, "userChannelID", "UserChannelID", "channelNO", "channelNum", "num")
        channel_id = _first_text(ch, "channelID", "ChannelID", "id", "ID")
        time_shift_minutes = _first_int(ch, "timeShiftLength", "TimeShiftLength", "timeShiftDuration")
        fcc_ip, fcc_port, fec_port = _parse_stream_params(ch)
        group_name = _first_text(
            ch,
            "groupName",
            "GroupName",
            "channelGroup",
            "ChannelGroup",
            "channelGroupName",
            "ChannelGroupName",
            "category",
            "Category",
            "categoryName",
            "CategoryName",
            "channelTypeName",
            "ChannelTypeName",
            "subjectName",
            "SubjectName",
            "genre",
            "Genre",
        )
        channels.append({
            "num": int(user_chan_id) if user_chan_id.isdigit() else 0,
            "name": name,
            "category": _channel_category_from_group(group_name, name),
            "operator_group": _clean_group_name(group_name),
            "ip": ip,
            "port": port,
            "channel_id": channel_id,
            "user_channel_id": user_chan_id,
            "is_hd": _truthy(_first_text(ch, "isHDChannel", "IsHDChannel", "isHD", "hd")),
            "time_shift": _truthy(_first_text(ch, "timeShift", "TimeShift", "timeshift")),
            "time_shift_minutes": time_shift_minutes,
            "fcc_ip": fcc_ip,
            "fcc_port": fcc_port,
            "fec_port": fec_port,
            "backtv_url": _first_text(ch, "timeShiftURL", "TimeShiftURL", "backtvURL", "BacktimeURL", "BackUrl"),
        })
    channels.sort(key=lambda x: (x["num"] or 9999, x["name"], x["ip"], x["port"]))
    return channels


_TIMESHIFT_URL_RE = re.compile(
    rb"https?://([\d.]+(?::\d+)?)/[^\s\"'<>]*(?:timeshift|backtv|backtime|catchup)[^\s\"'<>]*",
    re.IGNORECASE,
)


def _extract_epg_credentials(streams: dict[Any, bytes], stb_ip: str) -> dict[str, str]:
    """
    Scan STB→server TCP streams for EPG auth requests and extract:
    user_id, stb_id, epg_auth_host (ip:port).
    """
    result: dict[str, str] = {}
    epg_hosts: list[str] = []
    request_streams = {k: v for k, v in streams.items() if k[0] == stb_ip}
    for (src_ip, src_port, dst_ip, dst_port), data in request_streams.items():
        text = data.decode("utf-8", errors="replace")
        if b"/EPG/jsp/" in data or b"/EDS/jsp/" in data:
            epg_hosts.append(f"{dst_ip}:{dst_port}")
        # UserID from /EDS/jsp/AuthenticationURL?UserID=...
        if not result.get("epg_user_id"):
            m = re.search(r"/EDS/jsp/AuthenticationURL[^\r\n]*[?&]UserID=([^&\s\r\n/]+)", text, re.IGNORECASE)
            if m:
                uid = urllib.parse.unquote(m.group(1)).strip()
                if uid:
                    result["epg_user_id"] = uid
                    result.setdefault("epg_auth_host", f"{dst_ip}:{dst_port}")
        # STBID from POST body to ValidAuthenticationHWCTC.  Operators use
        # both URL query strings and x-www-form-urlencoded POST bodies, and
        # some firmwares lowercase every field name.
        if not result.get("epg_stb_id"):
            if any(marker in text for marker in (
                "ValidAuthenticationHWCU", "authLoginHWCU",
                "ValidAuthenticationHWCTC", "authLoginHWCTC",
            )):
                stbid = _extract_request_field(text, "STBID", "DeviceID", "TerminalID")
                if stbid:
                    result["epg_stb_id"] = stbid
                result.setdefault("epg_auth_host", f"{dst_ip}:{dst_port}")
        # The HWCU validation POST carries the device/profile fields required
        # to refresh a future legal session.  Persist field values only in
        # owner-local state; the status API and protocol manifest stay redacted.
        if any(marker in text for marker in (
            "ValidAuthenticationHWCU", "authLoginHWCU",
            "ValidAuthenticationHWCTC", "authLoginHWCTC",
        )):
            for source, destination in (
                ("STBType", "epg_stb_type"),
                ("STBVersion", "epg_stb_version"),
                ("SoftwareVersion", "epg_software_version"),
                ("NetUserID", "epg_net_user_id"),
                ("conntype", "epg_conn_type"),
                ("Lang", "epg_lang"),
                ("AccessUserName", "access_user_name"),
            ):
                if not result.get(destination):
                    value = _extract_request_field(text, source)
                    if value:
                        result[destination] = value
            if not result.get("epg_user_agent"):
                user_agent = re.search(r"(?im)^User-Agent:\s*([^\r\n]+)", text)
                if user_agent:
                    result["epg_user_agent"] = user_agent.group(1).strip()
        # EPG host from any /EPG/jsp/ or /EDS/jsp/ request
        if not result.get("epg_auth_host"):
            if b"/EPG/jsp/" in data or b"/EDS/jsp/" in data:
                result["epg_auth_host"] = f"{dst_ip}:{dst_port}"
    if epg_hosts:
        def _epg_host_priority(host: str) -> tuple[int, str]:
            try:
                port = int(host.rsplit(":", 1)[1])
            except (IndexError, ValueError):
                port = 0
            # 8082 is the standard IPTV EDS port.  A boot capture can also
            # contain SOAP/control traffic on another port before the EDS GET.
            return ({8082: 0, 80: 1, 8080: 2}.get(port, 10), host)
        result["epg_auth_host"] = sorted(set(epg_hosts), key=_epg_host_priority)[0]
    return result


def _extract_request_field(text: str, *field_names: str) -> str:
    """Return a URL/form/JSON request value without making field names case-sensitive."""
    if not text or not field_names:
        return ""
    names = "|".join(re.escape(name) for name in field_names)
    patterns = (
        # Query string and application/x-www-form-urlencoded body.
        rf"(?im)(?:^|[?&\r\n])(?:{names})=([^&\s\r\n]+)",
        # JSON portal payloads used by newer STB firmware.
        rf"(?is)\"(?:{names})\"\s*:\s*\"([^\"]+)\"",
    )
    for pattern in patterns:
        m = re.search(pattern, text)
        if m:
            value = urllib.parse.unquote_plus((m.group(1) or "").strip())
            if value:
                return value
    return ""


def _detect_timeshift_host(streams: dict[Any, bytes], channels: list[dict[str, Any]]) -> str:
    """Return first timeshift server host:port found in channels or HTTP traffic."""
    # 1. Check backtv_url field captured from channel list (may be rtsp:// or http://)
    for ch in channels:
        url = ch.get("backtv_url", "")
        if url:
            m = re.match(r"(?:https?|rtsp)://([\d.]+(?::\d+)?)/", url)
            if m:
                return m.group(1)
    # 2. Scan all HTTP traffic bodies for timeshift URLs
    for raw in streams.values():
        m = _TIMESHIFT_URL_RE.search(raw)
        if m:
            return m.group(1).decode("utf-8", errors="replace")
    return ""


def _extract_ctc_portal_auth(streams: dict[Any, bytes], stb_ip: str) -> dict[str, Any]:
    """Extract CTC portal auth crumbs from STB boot traffic.

    Enshan's Jiangsu Telecom flow obtains a portal UserToken through:
    CTCGetAuthInfo -> Authenticator -> /uploadAuthInfo.  We do not actively
    replay that regional flow here; this parser only records values already
    visible in STB traffic so the Web UI can show whether they were captured.
    """
    result: dict[str, Any] = {}
    if not stb_ip:
        return result

    def _host_from_request(text: str) -> str:
        m = re.search(r"(?im)^Host:\s*([^\r\n]+)", text)
        return m.group(1).strip() if m else ""

    def _header(text: str, name: str) -> str:
        m = re.search(rf"(?im)^{re.escape(name)}:\s*([^\r\n]+)", text)
        return m.group(1).strip() if m else ""

    def _remember_server(dst_ip: str, dst_port: int, text: str) -> None:
        if not result.get("portal_auth_host"):
            result["portal_auth_host"] = _host_from_request(text) or f"{dst_ip}:{dst_port}"
        result.setdefault("server_ip", dst_ip)
        result.setdefault("server_port", dst_port)

    for (src_ip, _src_port, dst_ip, dst_port), raw in streams.items():
        if src_ip != stb_ip:
            continue
        text = _decode_payload_text(raw)
        if "/auth?" in text or "/uploadAuthInfo" in text or "/getServiceList" in text or "/iptvepg/" in text:
            _remember_server(dst_ip, dst_port, text)
        if "/bj_stb/V1/STB/channelAcquire" in text or "channelAcquire" in text:
            _remember_server(dst_ip, dst_port, text)
            if not result.get("token_path"):
                m = re.search(r"(?im)^(?:POST|GET)\s+([^\s]+channelAcquire[^\s]*)", text)
                result["token_path"] = m.group(1).strip() if m else "/bj_stb/V1/STB/channelAcquire"
            if not result.get("user_token"):
                m = re.search(r'"UserToken"\s*:\s*"([^"]+)"', text)
                if m:
                    result["user_token"] = m.group(1).strip()
        if not result.get("epg_user_agent"):
            ua = _header(text, "User-Agent")
            if ua:
                result["epg_user_agent"] = ua
                if not result.get("epg_stb_type"):
                    stb_model = re.search(r"\b(?:IP811N|[A-Z]{2,}\d{3,}[A-Z0-9]*)\b", ua)
                    if stb_model:
                        result["epg_stb_type"] = stb_model.group(0)
        if not result.get("epg_user_id"):
            user_id = _extract_request_field(text, "UserID", "NetUserID")
            if user_id:
                result["epg_user_id"] = user_id
        if not result.get("epg_stb_id"):
            stb_id = _extract_request_field(text, "STBID", "DeviceID", "TerminalID")
            if stb_id:
                result["epg_stb_id"] = stb_id
        if not result.get("access_user_name"):
            access_user_name = _extract_request_field(text, "AccessUserName")
            if access_user_name:
                result["access_user_name"] = access_user_name
        if not result.get("epg_net_user_id"):
            net_user_id = _extract_request_field(text, "NetUserID")
            if net_user_id:
                result["epg_net_user_id"] = net_user_id
        if not result.get("epg_conn_type"):
            conn_type = _extract_request_field(text, "conntype", "ConnType")
            if conn_type:
                result["epg_conn_type"] = conn_type
        if not result.get("epg_lang"):
            lang = _extract_request_field(text, "Lang", "lang")
            if lang:
                result["epg_lang"] = lang
        if not result.get("epg_stb_type"):
            stb_type = _extract_request_field(text, "STBType", "DeviceType", "TerminalType")
            if stb_type:
                result["epg_stb_type"] = stb_type
        if not result.get("epg_stb_version"):
            stb_version = _extract_request_field(text, "STBVersion", "DeviceVersion", "TerminalVersion")
            if stb_version:
                result["epg_stb_version"] = stb_version
        if "/uploadAuthInfo" in text:
            result.setdefault("token_path", "/uploadAuthInfo")

    for (src_ip, src_port, dst_ip, _dst_port), raw in streams.items():
        if dst_ip != stb_ip:
            continue
        headers_bodies = _split_http_responses(raw)
        chunks = []
        if headers_bodies:
            for headers, body in headers_bodies:
                chunks.append(headers)
                chunks.append(body.decode("utf-8", errors="replace"))
        else:
            chunks.append(_decode_payload_text(raw))
        for text in chunks:
            if not result.get("ctc_auth_info"):
                m = re.search(r"CTCGetAuthInfo\(['\"]([^'\"]+)['\"]\)", text)
                if m:
                    result["ctc_auth_info"] = m.group(1).strip()
                    result.setdefault("server_ip", src_ip)
                    result.setdefault("server_port", src_port)
            if not result.get("user_token"):
                m = re.search(r"(?im)^Set-Cookie:\s*UserToken=([^;\r\n]+)", text)
                if not m:
                    m = re.search(r"CTCSetConfig\s*\(\s*['\"]UserToken['\"]\s*,\s*['\"]([^'\"]+)['\"]", text)
                if not m:
                    m = re.search(r'"(?:userToken|UserToken)"\s*:\s*"([^"]+)"', text)
                if m:
                    result["user_token"] = urllib.parse.unquote(m.group(1)).strip()
                    result.setdefault("token_path", "/uploadAuthInfo")
                    result.setdefault("server_ip", src_ip)
                    result.setdefault("server_port", src_port)
            if not result.get("epg_auth_host"):
                m = re.search(r'"epgDomain"\s*:\s*"(https?://[^"/]+(?::\d+)?)', text)
                if m:
                    result["epg_auth_host"] = urllib.parse.urlparse(m.group(1)).netloc
            if not result.get("token_expired_time"):
                m = re.search(r'"tokenExpiredTime"\s*:\s*"([^"]+)"', text)
                if m:
                    result["token_expired_time"] = m.group(1).strip()
            if not result.get("x_frame_session_id"):
                m = re.search(r"(?im)^X-Frame-Sessionid:\s*([^\r\n]+)", text)
                if m:
                    result["x_frame_session_id"] = m.group(1).strip()
                    result.setdefault("server_ip", src_ip)
                    result.setdefault("server_port", src_port)
    return result




def analyze_pcap_for_channels(pcap_path: str, stb_ip: str) -> list[dict[str, Any]]:
    """Main analysis entry point: returns channel list extracted from pcap."""
    streams = _reassemble_tcp_streams(pcap_path)

    # Find all response streams (server -> STB)
    response_streams = {
        k: v
        for k, v in streams.items()
        if k[2] == stb_ip and k[0] != stb_ip
    }

    all_channels: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    channel_catalog: dict[str, dict[str, str]] = {}

    for key, raw in response_streams.items():
        responses = _split_http_responses(raw)
        for headers, body in responses:
            if not body:
                continue
            if b"PC_ChannelList" in body and b"channelAllList" in body:
                channel_catalog.update(_parse_pc_channel_catalog(body))
            # Beijing Unicom / Hisense IP811N channelAcquire JSON response
            # uses the misspelled channleInfoStruct field.
            if (
                b"channleInfoStruct" in body
                or b"channelInfoStruct" in body
                or (b"channelURL" in body and b"channelName" in body)
            ):
                parsed = _parse_channel_acquire_json(body)
                for ch in parsed:
                    k = f"{ch['ip']}:{ch['port']}"
                    if k not in seen_keys:
                        seen_keys.add(k)
                        all_channels.append(ch)
            # CTC/CU channel middleware pages. Jiangsu Telecom uses
            # frameset_builder.jsp + jsSetConfig and serves a GBK, gzip/chunked body.
            elif b"SetConfig" in body and (b"'Channel'" in body or b'"Channel"' in body):
                parsed = _parse_chanlist_html(body)
                for ch in parsed:
                    k = f"{ch['ip']}:{ch['port']}"
                    if k not in seen_keys:
                        seen_keys.add(k)
                        all_channels.append(ch)
            # Look for VSP JSON channel list
            elif b'"channelDetails"' in body and b'"channelNO"' in body:
                parsed = _parse_vsp_json(body)
                for ch in parsed:
                    k = f"{ch['ip']}:{ch['port']}"
                    if k not in seen_keys:
                        seen_keys.add(k)
                        all_channels.append(ch)

        # Fallback: no complete HTTP responses found in this stream, but the raw
        # bytes contain channel URL data.  This happens when the first TCP
        # segments of the response (carrying HTTP headers + JSON array opening)
        # were not captured, leaving only the body fragment starting mid-array.
        if not responses and b"channelURL" in raw and b"channelName" in raw:
            parsed = _parse_channel_acquire_json(raw)
            for ch in parsed:
                k = f"{ch['ip']}:{ch['port']}"
                if k not in seen_keys:
                    seen_keys.add(k)
                    all_channels.append(ch)

        if not responses and b"SetConfig" in raw and (b"'Channel'" in raw or b'"Channel"' in raw):
            parsed = _parse_chanlist_html(raw)
            for ch in parsed:
                k = f"{ch['ip']}:{ch['port']}"
                if k not in seen_keys:
                    seen_keys.add(k)
                    all_channels.append(ch)

    for channel in all_channels:
        metadata = channel_catalog.get(str(channel.get("channel_id") or ""))
        if not metadata:
            continue
        if metadata.get("name") and not channel.get("name"):
            channel["name"] = metadata["name"]
        if metadata.get("category") and channel.get("category") == "其它频道":
            channel["category"] = metadata["category"]
        if metadata.get("operator_group") and not channel.get("operator_group"):
            channel["operator_group"] = metadata["operator_group"]

    all_channels.sort(key=lambda x: x["num"])
    return all_channels


class StbDiscoveryService:
    STATUS_IDLE = "idle"
    STATUS_CAPTURING = "capturing"
    STATUS_ANALYZING = "analyzing"
    STATUS_DONE = "done"
    STATUS_ERROR = "error"

    def __init__(
        self,
        logger: AppLogger,
        token_store: Any | None = None,
        archive_dir: Path | None = None,
    ) -> None:
        self.logger = logger
        self.token_store = token_store
        token_path = getattr(token_store, "path", None)
        self.archive_dir = archive_dir or (
            Path(token_path).parent / "stb-captures" if token_path else None
        )
        self._lock = threading.RLock()
        self._state: dict[str, Any] = {
            "status": self.STATUS_IDLE,
            "stb_ip": None,
            "stb_mac": "",
            "interface": None,
            "started_at": None,
            "stopped_at": None,
            "error": None,
            "channels": [],
            "channel_count": 0,
            "auth_info": {},
            "archived_pcap": "",
            "protocol_artifacts": {"saved": False},
        }
        self._proc: subprocess.Popen | None = None
        self._pcap_path: str | None = None
        self._worker_thread: threading.Thread | None = None

    def _pcap_meta_locked(self) -> dict[str, Any]:
        path = self._pcap_path
        if not path or not os.path.exists(path):
            return {"pcap_available": False, "pcap_size": 0}
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        return {"pcap_available": size > 0, "pcap_size": size}

    def pcap_path(self) -> str:
        with self._lock:
            path = self._pcap_path or ""
            if path and os.path.exists(path):
                return path
            return ""

    def archive_path(self, name: str) -> Path | None:
        """Resolve one persisted capture without accepting path traversal."""
        name = str(name or "").strip()
        if not self.archive_dir or not name or Path(name).name != name:
            return None
        if not name.startswith("stb-boot-") or not name.endswith(".pcap"):
            return None
        path = self.archive_dir / name
        return path if path.is_file() else None

    def list_archives(self) -> list[dict[str, Any]]:
        """Return only non-sensitive metadata for locally persisted captures."""
        if not self.archive_dir:
            return []
        result: list[dict[str, Any]] = []
        for path in self.archive_dir.glob("stb-boot-*.pcap"):
            try:
                stat = path.stat()
            except OSError:
                continue
            result.append({
                "name": path.name,
                "size": stat.st_size,
                "created_at": int(stat.st_mtime),
                "has_manifest": (self.archive_dir / f"{path.stem}.artifacts" / "manifest.json").is_file(),
            })
        return sorted(result, key=lambda item: (item["created_at"], item["name"]), reverse=True)

    def delete_archive(self, name: str) -> dict[str, Any]:
        """Delete one explicitly selected persisted capture and its metadata."""
        path = self.archive_path(name)
        if path is None:
            raise FileNotFoundError("历史抓包不存在")
        size = path.stat().st_size
        artifact_dir = path.parent / f"{path.stem}.artifacts"
        path.unlink()
        artifacts_deleted = False
        if artifact_dir.is_dir():
            shutil.rmtree(artifact_dir)
            artifacts_deleted = True
        with self._lock:
            if self._state.get("archived_pcap") == path.name:
                self._state["archived_pcap"] = ""
                self._state["protocol_artifacts"] = {"saved": False}
        return {
            "name": path.name,
            "size": size,
            "artifacts_deleted": artifacts_deleted,
        }

    def latest_archive_path(self) -> Path | None:
        archives = self.list_archives()
        return self.archive_path(str(archives[0]["name"])) if archives else None

    def _archive_pcap(self, pcap_path: str | None, stopped_at: float) -> str:
        """Persist a completed raw capture in the data volume for offline replay.

        PCAP files can contain IPTV credentials.  They are therefore kept
        locally only, permissioned for the container user, excluded from the
        JSON global backup, and never emitted through status/log responses.
        """
        if not self.archive_dir or not pcap_path or not os.path.isfile(pcap_path):
            return ""
        try:
            self.archive_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(stopped_at))
            suffix = f"-{time.time_ns() % 1_000_000_000:09d}"
            target = self.archive_dir / f"stb-boot-{stamp}{suffix}.pcap"
            shutil.copy2(pcap_path, target)
            os.chmod(target, 0o600)
            return target.name
        except Exception as exc:
            self.logger.warning(f"STB 原始抓包归档失败：{exc}")
            return ""

    @staticmethod
    def _write_private_artifact(path: Path, content: bytes) -> None:
        """Atomically write a credential-bearing artifact with owner-only mode."""
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temp_path = path.with_name(f".{path.name}.{time.time_ns()}.tmp")
        try:
            temp_path.write_bytes(content)
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, path)
            os.chmod(path, 0o600)
        finally:
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except OSError:
                pass

    def _persist_protocol_artifacts(
        self,
        pcap_path: str,
        archive_name: str,
        streams: dict[tuple[str, int, str, int], bytes] | None = None,
    ) -> dict[str, Any]:
        """Persist only a redacted protocol-capture summary beside a PCAP.

        The raw PCAP remains the user-controlled local capture.  This helper
        deliberately does *not* duplicate request bodies, authentication
        forms, token values, cookies, or complete response streams.  That
        keeps restart diagnostics useful without creating a new credential
        export surface; the summary is also excluded from global JSON backup.
        """
        if not self.archive_dir:
            return {"saved": False, "reason": "archive_unconfigured"}
        streams = streams if streams is not None else _reassemble_tcp_streams(pcap_path)
        artifact_dir = self.archive_dir / f"{Path(archive_name).stem}.artifacts"
        artifact_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        selected: list[dict[str, Any]] = []
        response_stream_keys: set[tuple[str, int, str, int]] = set()
        auth_paths = (
            "/eds/jsp/authenticationurl",
            "/epg/jsp/authlogin",
            "/epg/jsp/validauthentication",
            "/uploadauthinfo",
            "/getservicelist",
        )
        channel_paths = ("channelacquire", "getchannellist", "getallchannel")
        for stream_key, raw in streams.items():
            src_ip, src_port, dst_ip, dst_port = stream_key
            for method, path, request_raw, cookie_names, header_names in _iter_http_requests(raw):
                normalized_path = urllib.parse.urlsplit(path).path
                lowered = normalized_path.lower()
                category = ""
                if any(marker in lowered for marker in auth_paths):
                    category = "auth_form"
                elif any(marker in lowered for marker in channel_paths):
                    category = "channel_request"
                if not category:
                    continue
                reverse_key = (dst_ip, dst_port, src_ip, src_port)
                response_raw = streams.get(reverse_key, b"")
                if response_raw:
                    response_stream_keys.add(reverse_key)
                selected.append({
                    "kind": category,
                    "method": method,
                    "path": normalized_path,
                    "request_bytes": len(request_raw),
                    "request_has_cookie": bool(cookie_names),
                    "request_header_names": header_names,
                    "response_observed": bool(response_raw),
                    "response_sets_cookie": bool(_response_cookie_names(response_raw)),
                })
        manifest = {
            "schema_version": 1,
            "source_pcap": Path(archive_name).name,
            "created_at": int(time.time()),
            "global_backup_excluded": True,
            "auth_form_count": sum(item["kind"] == "auth_form" for item in selected),
            "channel_request_count": sum(item["kind"] == "channel_request" for item in selected),
            "response_stream_count": len(response_stream_keys),
            "artifacts": selected,
        }
        self._write_private_artifact(
            artifact_dir / "manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"),
        )
        return {
            "saved": bool(selected),
            "auth_forms": manifest["auth_form_count"],
            "channel_requests": manifest["channel_request_count"],
            "response_streams": manifest["response_stream_count"],
        }

    def reanalyze_latest_archive(self, stb_ip: str) -> dict[str, Any]:
        """Rebuild discovery state from the newest persisted PCAP.

        This is intentionally offline: it does not start tcpdump or touch the
        network interface, so parser improvements can be tested without
        requiring the user to reboot the STB again.
        """
        if not self.archive_dir:
            raise RuntimeError("未配置 STB 抓包归档目录")
        archives = sorted(
            self.archive_dir.glob("stb-boot-*.pcap"),
            key=lambda path: path.stat().st_mtime,
        )
        if not archives:
            raise RuntimeError("暂无已归档的 STB 抓包文件")
        with self._lock:
            if self._state["status"] == self.STATUS_CAPTURING:
                raise RuntimeError("正在捕获 STB 流量，请停止后再离线解析")

        pcap_path = str(archives[-1])
        streams = _reassemble_tcp_streams(pcap_path)
        protocol_artifacts = self._persist_protocol_artifacts(pcap_path, archives[-1].name, streams)
        channels = analyze_pcap_for_channels(pcap_path, stb_ip)
        timeshift_host = _detect_timeshift_host(streams, channels)
        auth_info = _extract_dhcp_from_pcap(pcap_path)
        epg_creds = _extract_epg_credentials(streams, stb_ip)
        portal_auth = _extract_ctc_portal_auth(streams, stb_ip)
        if portal_auth.get("epg_user_id") and not epg_creds.get("epg_user_id"):
            epg_creds["epg_user_id"] = str(portal_auth["epg_user_id"])
        if portal_auth.get("epg_stb_id") and not epg_creds.get("epg_stb_id"):
            epg_creds["epg_stb_id"] = str(portal_auth["epg_stb_id"])
        if portal_auth.get("portal_auth_host") and not epg_creds.get("epg_auth_host"):
            epg_creds["epg_auth_host"] = str(portal_auth["portal_auth_host"])
        for key in ("epg_user_agent", "epg_stb_type", "epg_stb_version", "access_user_name"):
            if portal_auth.get(key) and not epg_creds.get(key):
                epg_creds[key] = str(portal_auth[key])
        token = str(portal_auth.get("user_token") or "").strip()
        if token and self.token_store:
            self.token_store.save_token({
                "token": token,
                "sip": stb_ip,
                "sport": None,
                "dip": portal_auth.get("server_ip", ""),
                "dport": portal_auth.get("server_port"),
                "path": portal_auth.get("token_path") or "/uploadAuthInfo",
                "captured_at": int(time.time()),
            })
        safe_portal_auth: dict[str, Any] = {}
        for key in ("portal_auth_host", "server_ip", "server_port", "token_path"):
            if portal_auth.get(key):
                safe_portal_auth[key] = portal_auth[key]
        safe_portal_auth["has_ctc_auth_info"] = bool(portal_auth.get("ctc_auth_info"))
        safe_portal_auth["has_upload_user_token"] = bool(portal_auth.get("user_token"))
        safe_portal_auth["has_x_frame_session_id"] = bool(portal_auth.get("x_frame_session_id"))
        with self._lock:
            self._state.update({
                "status": self.STATUS_DONE,
                "stb_ip": stb_ip,
                "stopped_at": time.time(),
                "error": None,
                "channels": channels,
                "channel_count": len(channels),
                "auth_info": auth_info,
                "timeshift_host": timeshift_host,
                "epg_creds": epg_creds,
                "portal_auth": safe_portal_auth,
                "archived_pcap": archives[-1].name,
                "protocol_artifacts": protocol_artifacts,
            })
            self._state.update(self._pcap_meta_locked())
            return dict(self._state)

    def _live_watcher(self, pcap_path: str, stb_ip: str) -> None:
        while True:
            time.sleep(3)
            with self._lock:
                if self._state["status"] != self.STATUS_CAPTURING:
                    break
            try:
                channels = analyze_pcap_for_channels(pcap_path, stb_ip)
                auth_info = _extract_dhcp_from_pcap(pcap_path)
                has_auth = bool(auth_info.get("mac") or auth_info.get("assigned_ip"))
                with self._lock:
                    if self._state["status"] == self.STATUS_CAPTURING:
                        self._state["live_channel_count"] = len(channels)
                        self._state["live_has_auth"] = has_auth
            except Exception:
                pass

    def runtime_check(self) -> dict[str, Any]:
        ok = shutil.which("tcpdump") is not None
        return {"ok": ok, "errors": [] if ok else ["缺少依赖命令：tcpdump"]}

    def status(self) -> dict[str, Any]:
        with self._lock:
            state = dict(self._state)
            state.update(self._pcap_meta_locked())
        archives = self.list_archives()
        state["archive_count"] = len(archives)
        state["latest_archive"] = archives[0] if archives else None
        return state

    def start(
        self,
        stb_ip: str,
        interface: str = "any",
        full_capture: bool = False,
        stb_mac: str = "",
    ) -> None:
        mac = normalize_mac(stb_mac)
        rt = self.runtime_check()
        if not rt["ok"]:
            raise RuntimeError("；".join(rt["errors"]))
        with self._lock:
            if self._state["status"] == self.STATUS_CAPTURING:
                raise RuntimeError("已有一个捕获任务正在进行")
            if self._pcap_path and os.path.exists(self._pcap_path):
                try:
                    os.unlink(self._pcap_path)
                except Exception:
                    pass
            self._pcap_path = tempfile.mktemp(suffix=".pcap", prefix="stb_discovery_")
            self._state = {
                "status": self.STATUS_CAPTURING,
                "stb_ip": stb_ip,
                "stb_mac": mac,
                "interface": interface,
                "full_capture": bool(full_capture),
                "started_at": time.time(),
                "stopped_at": None,
                "error": None,
                "channels": [],
                "channel_count": 0,
                "live_channel_count": 0,
                "live_has_auth": False,
                "auth_info": {},
                "pcap_available": False,
                "pcap_size": 0,
                "protocol_artifacts": {"saved": False},
            }
        cmd = [
            "tcpdump",
            "-i", interface,
            "-s", "0",
            "-w", self._pcap_path,
        ]
        if not full_capture:
            # Keep the complete STB session for later offline analysis: RTSP
            # control is TCP, while the negotiated media path can be UDP/RTP.
            # DHCP is included before the STB address is assigned.
            #
            # Prefer the STB MAC when it is known: the address is assigned by
            # DHCP and may not exist yet when capture starts, or may change on
            # renegotiation, so filtering by IP can silently capture nothing.
            # ether host matches at layer 2 and is immune to both problems.
            # DHCP stays in the expression because it happens before the STB
            # has an address, and it carries the credentials we need.
            if mac:
                cmd.append(f"ether host {mac} or (udp and (port 67 or port 68))")
            else:
                cmd.append(f"host {stb_ip} or (udp and (port 67 or port 68))")
        self.logger.info(
            f"开始捕获 STB 开机流量：STB={stb_ip}"
            f"{f'，MAC={mac}' if mac else ''}，接口={interface}，文件={self._pcap_path}"
        )
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except Exception as exc:
            with self._lock:
                self._state["status"] = self.STATUS_ERROR
                self._state["error"] = str(exc)
            raise
        threading.Thread(
            target=self._live_watcher,
            args=(self._pcap_path, stb_ip),
            daemon=True,
            name="stb-live-watcher",
        ).start()

    def stop(self) -> dict[str, Any]:
        proc = None
        pcap_path = None
        stb_ip = None
        with self._lock:
            if self._state["status"] != self.STATUS_CAPTURING:
                return dict(self._state)
            proc = self._proc
            pcap_path = self._pcap_path
            stb_ip = self._state["stb_ip"]
            self._state["status"] = self.STATUS_ANALYZING
            self._state["stopped_at"] = time.time()

        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        archived_pcap = self._archive_pcap(pcap_path, float(self._state.get("stopped_at") or time.time()))
        if archived_pcap:
            with self._lock:
                self._state["archived_pcap"] = archived_pcap

        def _analyze() -> None:
            try:
                time.sleep(0.5)  # let pcap flush
                channels: list[dict[str, Any]] = []
                auth_info: dict[str, Any] = {}
                timeshift_host: str = ""
                epg_creds: dict[str, str] = {}
                portal_auth: dict[str, Any] = {}
                protocol_artifacts: dict[str, Any] = {"saved": False}
                if pcap_path and os.path.exists(pcap_path):
                    streams = _reassemble_tcp_streams(pcap_path)
                    protocol_artifacts = self._persist_protocol_artifacts(
                        pcap_path,
                        archived_pcap or Path(pcap_path).name,
                        streams,
                    )
                    channels = analyze_pcap_for_channels(pcap_path, stb_ip or "")
                    timeshift_host = _detect_timeshift_host(streams, channels)
                    auth_info = _extract_dhcp_from_pcap(pcap_path)
                    epg_creds = _extract_epg_credentials(streams, stb_ip or "")
                    portal_auth = _extract_ctc_portal_auth(streams, stb_ip or "")
                    if portal_auth.get("epg_user_id") and not epg_creds.get("epg_user_id"):
                        epg_creds["epg_user_id"] = str(portal_auth.get("epg_user_id") or "")
                    if portal_auth.get("epg_stb_id") and not epg_creds.get("epg_stb_id"):
                        epg_creds["epg_stb_id"] = str(portal_auth.get("epg_stb_id") or "")
                    if portal_auth.get("portal_auth_host") and not epg_creds.get("epg_auth_host"):
                        epg_creds["epg_auth_host"] = str(portal_auth.get("portal_auth_host") or "")
                    for key in ("epg_user_agent", "epg_stb_type", "epg_stb_version", "access_user_name"):
                        if portal_auth.get(key) and not epg_creds.get(key):
                            epg_creds[key] = str(portal_auth.get(key) or "")
                    token = str(portal_auth.get("user_token") or "").strip()
                    if token and self.token_store:
                        self.token_store.save_token({
                            "token": token,
                            "sip": stb_ip or "",
                            "sport": None,
                            "dip": portal_auth.get("server_ip", ""),
                            "dport": portal_auth.get("server_port"),
                            "path": portal_auth.get("token_path") or "/uploadAuthInfo",
                            "captured_at": int(time.time()),
                        })
                    # Keep the latest pcap for one-click export. Reset or a new capture removes it.
                safe_portal_auth: dict[str, Any] = {}
                for key in ("portal_auth_host", "server_ip", "server_port", "token_path"):
                    if portal_auth.get(key):
                        safe_portal_auth[key] = portal_auth[key]
                safe_portal_auth["has_ctc_auth_info"] = bool(portal_auth.get("ctc_auth_info"))
                safe_portal_auth["has_upload_user_token"] = bool(portal_auth.get("user_token"))
                safe_portal_auth["has_x_frame_session_id"] = bool(portal_auth.get("x_frame_session_id"))
                with self._lock:
                    self._state["status"] = self.STATUS_DONE
                    self._state["channels"] = channels
                    self._state["channel_count"] = len(channels)
                    self._state["auth_info"] = auth_info
                    self._state["timeshift_host"] = timeshift_host
                    self._state["epg_creds"] = epg_creds
                    self._state["portal_auth"] = safe_portal_auth
                    self._state["protocol_artifacts"] = protocol_artifacts
                    self._state.update(self._pcap_meta_locked())
                has_auth = bool(auth_info.get("mac") or auth_info.get("assigned_ip"))
                self.logger.info(
                    f"STB 频道发现完成：共发现 {len(channels)} 个频道，"
                    f"DHCP认证字段：{'已捕获' if has_auth else '未捕获'}，"
                    f"EPG字段：{'已捕获' if epg_creds else '未捕获'}，"
                    f"门户会话字段：{'已捕获' if portal_auth else '未捕获'}，"
                    f"原始PCAP归档：{'已保存' if archived_pcap else '失败'}"
                )
            except Exception as exc:
                self.logger.error(f"STB 频道发现分析失败：{exc}")
                with self._lock:
                    self._state["status"] = self.STATUS_ERROR
                    self._state["error"] = str(exc)

        t = threading.Thread(target=_analyze, daemon=True)
        t.start()
        with self._lock:
            return dict(self._state)

    def reset(self) -> None:
        with self._lock:
            if self._proc:
                try:
                    self._proc.terminate()
                except Exception:
                    pass
                self._proc = None
            if self._pcap_path and os.path.exists(self._pcap_path or ""):
                try:
                    os.unlink(self._pcap_path)
                except Exception:
                    pass
                self._pcap_path = None
            self._state = {
                "status": self.STATUS_IDLE,
                "stb_ip": None,
                "interface": None,
                "started_at": None,
                "stopped_at": None,
                "error": None,
                "channels": [],
                "channel_count": 0,
                "auth_info": {},
                "archived_pcap": "",
                "protocol_artifacts": {"saved": False},
                "pcap_available": False,
                "pcap_size": 0,
            }
