"""Tests for local-only persistence of an authorized EPG recovery key."""

import json
import stat

import app as app_module
from services.storage_service import LocalSecretStore, SettingsStore


def test_epg_key_is_persistent_but_absent_from_settings_and_json_backup(tmp_path, monkeypatch):
    settings_path = tmp_path / "settings.json"
    key_path = tmp_path / "epg-key.secret"
    secret_value = "87654321"
    settings = SettingsStore(settings_path)
    secret_store = LocalSecretStore(key_path)
    monkeypatch.setattr(app_module, "settings_store", settings)
    monkeypatch.setattr(app_module, "epg_key_store", secret_store)

    client = app_module.app.test_client()
    saved = client.post("/api/settings", json={
        "auto_epg": False,
        "epg_des3_key": secret_value,
    })

    assert saved.status_code == 200
    response_settings = saved.get_json()["data"]
    assert response_settings["epg_des3_key"] == ""
    assert response_settings["epg_des3_key_configured"] is True
    assert secret_store.get_epg_key() == secret_value
    assert LocalSecretStore(key_path).get_epg_key() == secret_value
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert secret_value not in settings_path.read_text(encoding="utf-8")

    fetched = client.get("/api/settings")
    assert secret_value not in fetched.data.decode("utf-8")

    exported = client.post("/api/backup/export", json={"modules": ["settings"]})
    payload = json.loads(exported.data)
    assert secret_value not in exported.data.decode("utf-8")
    assert payload["settings"]["epg_des3_key"] == ""
    assert payload["settings"]["epg_des3_key_configured"] is True

    internal = app_module._with_local_epg_key(settings.load())
    assert internal["epg_des3_key"] == secret_value
