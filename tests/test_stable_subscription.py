"""Stable subscription URLs must survive source-address and token refreshes."""

from __future__ import annotations

import app as app_module
from flask import Response

from services.storage_service import ChannelStore, OperatorChannelStore, SettingsStore, SubscriptionStore


def _install_catalog(tmp_path, monkeypatch, *, host="239.1.2.3", port=5000):
    channels = ChannelStore(tmp_path / "channels.json")
    channels.save_rows([{
        "key": f"{host}:{port}", "host": host, "port": port,
        "name": "News", "category": "其它频道", "tvg_id": "news",
        "fcc_ip": "10.0.0.1", "fcc_port": 9000,
    }])
    operators = OperatorChannelStore(tmp_path / "operator_channels.json")
    operators.save_dict({
        f"{host}:{port}": {
            "key": f"{host}:{port}", "host": host, "port": port,
            "name": "News", "category": "其它频道", "channel_id": "1001",
            "time_shift": True, "time_shift_days": 10080,
            "backtv_url": "rtsp://10.0.0.5/private?token=secret",
            "fcc_ip": "10.0.0.1", "fcc_port": 9000,
        }
    })
    settings = SettingsStore(tmp_path / "settings.json")
    subscription = SubscriptionStore(tmp_path / "subscription_candidates.json")
    settings.save({
        "http_host": "192.168.3.6", "http_port": 5140,
        "rtp2httpd_path_prefix": "/app/rtp2httpd",
        "catchup_enabled": True, "catchup_days": 7,
        "epg_url": "https://example.invalid/epg.xml",
    })
    monkeypatch.setattr(app_module, "channel_store", channels)
    monkeypatch.setattr(app_module, "operator_channel_store", operators)
    monkeypatch.setattr(app_module, "settings_store", settings)
    monkeypatch.setattr(app_module, "subscription_store", subscription)
    return channels, operators


def test_dynamic_subscription_uses_stable_live_and_catchup_urls(tmp_path, monkeypatch):
    _install_catalog(tmp_path, monkeypatch)

    response = app_module.app.test_client().get("/playlist.m3u", base_url="http://192.168.3.6:8788")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "http://192.168.3.6:8788/live/c-1001" in text
    assert "http://192.168.3.6:8788/catchup/c-1001?playseek=" in text
    assert "rtsp://" not in text
    assert "10.0.0.1" not in text


def test_stable_live_url_tracks_current_operator_source(tmp_path, monkeypatch):
    channels, operators = _install_catalog(tmp_path, monkeypatch)
    operators.save_dict({
        "239.9.9.9:6000": {
            "key": "239.9.9.9:6000", "host": "239.9.9.9", "port": 6000,
            "name": "News", "category": "其它频道", "channel_id": "1001",
            "fcc_ip": "10.0.0.2", "fcc_port": 9001,
        }
    })
    channels.save_rows([{
        "key": "239.9.9.9:6000", "host": "239.9.9.9", "port": 6000,
        "name": "News", "category": "其它频道",
    }])

    response = app_module.app.test_client().get("/live/c-1001")

    assert response.status_code == 307
    assert "/app/rtp2httpd/rtp/239.9.9.9:6000" in response.headers["Location"]
    assert "fcc=10.0.0.2:9001" in response.headers["Location"]


def test_stable_catchup_delegates_using_current_internal_key(tmp_path, monkeypatch):
    _install_catalog(tmp_path, monkeypatch)
    observed = {}

    def fake_catchup(key):
        observed["key"] = key
        return Response(b"G" * 188, mimetype="video/mp2t")

    monkeypatch.setattr(app_module, "hls_catchup", fake_catchup)
    response = app_module.app.test_client().get("/catchup/c-1001?playseek=20260901120000-20260901120500")

    assert response.status_code == 200
    assert observed["key"] == "239.1.2.3_5000"


def test_hls_and_epg_subscriptions_have_fixed_entrypoints(tmp_path, monkeypatch):
    _install_catalog(tmp_path, monkeypatch)
    client = app_module.app.test_client()

    hls = client.get("/playlist-hls.m3u", base_url="http://192.168.3.6:8788")
    epg = client.get("/epg.xml")

    assert hls.status_code == 200
    assert "http://192.168.3.6:8788/live/c-1001?format=hls" in hls.get_data(as_text=True)
    assert epg.status_code == 307
    assert epg.headers["Location"] == "https://example.invalid/epg.xml"


def test_manual_channel_stable_id_survives_metadata_edit(tmp_path):
    store = ChannelStore(tmp_path / "channels.json")
    store.save_rows([{
        "key": "239.1.2.3:5000", "host": "239.1.2.3", "port": 5000,
        "name": "Original", "category": "其它频道",
    }])
    before = store.get("239.1.2.3:5000")["stable_id"]
    store.patch_metadata("239.1.2.3:5000", {"name": "Renamed", "category": "其它频道"})

    assert store.get("239.1.2.3:5000")["stable_id"] == before


def test_subscription_candidate_selection_filters_dynamic_playlist(tmp_path, monkeypatch):
    _install_catalog(tmp_path, monkeypatch)
    subscription = app_module.SubscriptionStore(tmp_path / "subscription_candidates.json")
    subscription.save([])
    monkeypatch.setattr(app_module, "subscription_store", subscription)
    client = app_module.app.test_client()

    empty = client.get("/playlist.m3u", base_url="http://192.168.3.6:8788")
    assert "/live/c-1001" not in empty.get_data(as_text=True)

    updated = client.post("/api/subscription/candidates", json={"action": "add", "stable_ids": ["c-1001"]})
    assert updated.status_code == 200
    assert updated.get_json()["data"]["total_candidates"] == 1
    selected = client.get("/playlist.m3u", base_url="http://192.168.3.6:8788")
    assert "/live/c-1001" in selected.get_data(as_text=True)


def test_channels_api_exposes_subscription_candidate_state(tmp_path, monkeypatch):
    _install_catalog(tmp_path, monkeypatch)
    response = app_module.app.test_client().get("/api/channels")
    payload = response.get_json()["data"]

    assert response.status_code == 200
    assert payload["channels"][0]["stable_id"] == "c-1001"
    assert payload["channels"][0]["subscription_candidate"] is True
