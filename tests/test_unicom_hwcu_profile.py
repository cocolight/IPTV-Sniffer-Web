"""Regression coverage for the explicit China Unicom Huawei HWCU profile."""

from pathlib import Path

import pytest

from services.epg_refresh_service import refresh_backtv_urls
from services.log_service import AppLogger
from services.stb_discovery_service import _extract_epg_credentials


def test_explicit_hwcu_profile_never_falls_back_to_other_carrier_flows(monkeypatch, tmp_path):
    """An incomplete Unicom profile must fail before any network request."""
    import services.epg_refresh_service as refresh

    called = False

    def unexpected_request(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("network must not be reached with incomplete configuration")

    monkeypatch.setattr(refresh, "_request_text", unexpected_request)
    with pytest.raises(ValueError, match="联通 HWCU 回看需要已合法配置"):
        refresh_backtv_urls(
            {
                "epg_auth_profile": "cu_hwcu",
                "epg_auth_host": "epg.example:8082",
                "epg_user_id": "10001",
                "epg_stb_id": "STB-1",
            },
            {},
            {"mac": "aa:bb:cc:dd:ee:ff", "assigned_ip": "10.0.0.2"},
            AppLogger(Path(tmp_path) / "app.log"),
        )
    assert called is False


def test_hwcu_capture_extracts_stb_id_from_normal_form_post():
    streams = {
        ("10.0.0.2", 41000, "10.0.0.9", 33200): (
            b"POST /EPG/jsp/ValidAuthenticationHWCU.jsp HTTP/1.1\r\n"
            b"Host: 10.0.0.9:33200\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
            b"UserID=10001&STBID=STB-EXAMPLE&conntype=DHCP&SoftwareVersion=V100R001"
        )
    }

    credentials = _extract_epg_credentials(streams, "10.0.0.2")

    assert credentials["epg_stb_id"] == "STB-EXAMPLE"
    assert credentials["epg_software_version"] == "V100R001"
    assert credentials["epg_auth_host"] == "10.0.0.9:33200"
