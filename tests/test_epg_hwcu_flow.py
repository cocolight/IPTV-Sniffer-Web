import urllib.parse

import pytest

import services.epg_refresh_service as refresh
from services.log_service import AppLogger


class _Cookie:
    name = "JSESSIONID"
    value = "test-session"
    expires = None


def test_hwcu_refresh_uses_captured_portal_endpoints_and_fields(monkeypatch, tmp_path):
    """The local STB trace uses the HWCU, not the HWCTC, portal chain."""
    calls = []

    monkeypatch.setattr(refresh, "_build_opener_with_cookies", lambda: (object(), [_Cookie()]))
    monkeypatch.setattr(refresh, "_des_ecb_encrypt_hex", lambda *args, **kwargs: "AUTH")

    def fake_request(_opener, url, data=None, headers=None, timeout=15):
        calls.append((url, data, headers or {}))
        if url.endswith("/EDS/jsp/AuthenticationURL?UserID=10001&Action=Login"):
            return "EncryptToken='first-token'", "http://epg.example:33200/EPG/jsp/AuthenticationURL"
        if url.endswith("/EPG/jsp/authLoginHWCU.jsp"):
            return "EncryptToken='login-token'", url
        if url.endswith("/EPG/jsp/ValidAuthenticationHWCU.jsp"):
            return (
                "Authentication.CUSetConfig('UserToken', 'fresh-token');"
                "Authentication.CUSetConfig('stbid', 'session-stbid');"
                "Authentication.CUSetConfig('identityEncode', 'temporary-key');"
                "Authentication.CUSetConfig('UserID', 'session-user');"
                "Authentication.CUSetConfig('Lang', '2');"
                "Authentication.CUSetConfig('conntype', 'session-ipoe');"
                "Authentication.CUSetConfig('SupportHD', '2');",
                url,
            )
        if url.endswith("/EPG/jsp/getchannellistHWCU.jsp"):
            return (
                "CUSetConfig('Channel', 'ChannelURL=\"udp://239.1.1.1:1234\" "
                "TimeShiftURL=\"rtsp://example/shift\"')",
                url,
            )
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(refresh, "_request_text", fake_request)
    settings = {
        "epg_user_agent": "Captured-STB-UA",
        "epg_stb_type": "B860AV2.1U",
        "epg_stb_version": "v1",
        "epg_software_version": "software-v1",
        "epg_net_user_id": "aa:bb:cc:dd:ee:ff",
        "epg_conn_type": "DHCP",
        "epg_lang": "1",
        "epg_crypto_mode": "auto",
    }
    result = refresh._refresh_huawei_epg(
        settings=settings,
        operator_channels={},
        epg_auth_host="epg.example:8082",
        user_id="10001",
        stb_id="stb-1",
        des_key="12345678",
        mac_plain="aabbccddeeff",
        stb_ip="10.0.0.2",
        logger=AppLogger(tmp_path / "app.log"),
        portal_suffix="HWCU",
    )

    assert result["profile"] == "cu_hwcu"
    assert [urllib.parse.urlsplit(url).path for url, _, _ in calls] == [
        "/EDS/jsp/AuthenticationURL",
        "/EPG/jsp/authLoginHWCU.jsp",
        "/EPG/jsp/ValidAuthenticationHWCU.jsp",
        "/EPG/jsp/getchannellistHWCU.jsp",
    ]
    validate_data = calls[2][1]
    assert validate_data["NetUserID"] == "aa:bb:cc:dd:ee:ff"
    assert validate_data["mac"] == "aabbccddeeff"
    assert validate_data["conntype"] == "DHCP"
    assert validate_data["Lang"] == "1"
    assert validate_data["mac"] == "aabbccddeeff"
    assert validate_data["SoftwareVersion"] == "software-v1"
    assert "UserField" not in validate_data
    assert "IsSmartStb" not in validate_data
    assert calls[3][1]["conntype"] == "session-ipoe"
    assert calls[3][1]["UserToken"] == "fresh-token"
    assert calls[3][1]["tempKey"] == "temporary-key"
    assert calls[3][1]["stbid"] == "session-stbid"
    assert calls[3][1]["SupportHD"] == "2"
    assert calls[3][1]["UserID"] == "session-user"
    assert calls[3][1]["Lang"] == "2"
    assert urllib.parse.urlsplit(calls[3][2]["Referer"]).path == "/EPG/jsp/ValidAuthenticationHWCU.jsp"
    assert calls[3][2]["Origin"] == "http://epg.example:33200"


def test_hwcu_refresh_rejects_resignon_only_response(monkeypatch, tmp_path):
    monkeypatch.setattr(refresh, "_build_opener_with_cookies", lambda: (object(), [_Cookie()]))
    monkeypatch.setattr(refresh, "_des_ecb_encrypt_hex", lambda *args, **kwargs: "AUTH")

    def fake_request(_opener, url, data=None, headers=None, timeout=15):
        if "/EDS/jsp/AuthenticationURL" in url:
            return "EncryptToken='first-token'", "http://epg.example:33200/EPG/jsp/AuthenticationURL"
        if url.endswith("/EPG/jsp/authLoginHWCU.jsp"):
            return "EncryptToken='login-token'", url
        if url.endswith("/EPG/jsp/ValidAuthenticationHWCU.jsp"):
            return (
                "CUSetConfig('UserToken', 'fresh-token');"
                "CUSetConfig('stbid', 'session-stbid');",
                url,
            )
        if "getchannellist" in url:
            return "CUSetConfig('resignon', '1')", url
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(refresh, "_request_text", fake_request)
    with pytest.raises(RuntimeError, match="未返回频道配置块"):
        refresh._refresh_huawei_epg(
            settings={
                "epg_user_agent": "Captured-STB-UA",
                "epg_stb_type": "B860AV2.1U",
                "epg_stb_version": "v1",
            },
            operator_channels={},
            epg_auth_host="epg.example:8082",
            user_id="10001",
            stb_id="stb-1",
            des_key="12345678",
            mac_plain="aabbccddeeff",
            stb_ip="10.0.0.2",
            logger=AppLogger(tmp_path / "app.log"),
            portal_suffix="HWCU",
        )


def test_channel_parser_accepts_authentication_prefixed_config():
    channels = {}
    updated, rebuilt, total = refresh._update_backtv_from_channel_text(
        "Authentication.CUSetConfig('Channel', 'ChannelURL=\"udp://239.1.1.1:1234\" "
        "TimeShiftURL=\"rtsp://example/shift\"')",
        channels,
    )

    assert (updated, rebuilt, total) == (0, 1, 1)
