import urllib.parse

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
            return '<input name="UserToken" value="fresh-token">', url
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
    assert validate_data["mac"] == "aa:bb:cc:dd:ee:ff"
    assert validate_data["conntype"] == "DHCP"
    assert validate_data["Lang"] == "1"
    assert "UserField" not in validate_data
    assert "IsSmartStb" not in validate_data
    assert calls[3][1]["conntype"] == "DHCP"
