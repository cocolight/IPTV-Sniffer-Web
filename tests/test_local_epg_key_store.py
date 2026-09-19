"""Tests for plaintext local credential display and opt-in backup."""

import json
import stat
from pathlib import Path

import app as app_module
from services.log_service import AppLogger
from services.storage_service import LocalSecretStore, OperatorChannelStore, SettingsStore


def test_epg_key_is_visible_locally_and_only_in_opt_in_backup(tmp_path, monkeypatch):
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
        "iptv_password": "iptv-password",
        "epg_des3_key": secret_value,
    })

    assert saved.status_code == 200
    response_settings = saved.get_json()["data"]
    assert response_settings["epg_des3_key"] == secret_value
    assert response_settings["epg_des3_key_configured"] is True
    assert secret_store.get_epg_key() == secret_value
    assert LocalSecretStore(key_path).get_epg_key() == secret_value
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert secret_value not in settings_path.read_text(encoding="utf-8")

    fetched = client.get("/api/settings")
    assert fetched.get_json()["data"]["epg_des3_key"] == secret_value
    assert fetched.headers["Cache-Control"] == "no-store, max-age=0"

    exported = client.post("/api/backup/export", json={"modules": ["settings"]})
    payload = json.loads(exported.data)
    assert exported.headers["Cache-Control"] == "no-store, max-age=0"
    assert secret_value not in exported.data.decode("utf-8")
    assert "epg_des3_key" not in payload["settings"]
    assert "iptv_password" not in payload["settings"]
    assert payload["schema_version"] == 2

    default_export = client.get("/api/backup/export")
    assert default_export.headers["Cache-Control"] == "no-store, max-age=0"
    assert secret_value not in default_export.get_data(as_text=True)
    assert "iptv-password" not in default_export.get_data(as_text=True)

    credential_export = client.post("/api/backup/export", json={"modules": ["credentials"]})
    credential_payload = json.loads(credential_export.data)
    assert credential_payload["credentials"] == {
        "iptv_password": "iptv-password",
        "epg_des3_key": secret_value,
    }

    internal = app_module._with_local_epg_key(settings.load())
    assert internal["epg_des3_key"] == secret_value


def test_credentials_restore_is_explicit_and_settings_restore_preserves_local_credentials(tmp_path, monkeypatch):
    settings = SettingsStore(tmp_path / "settings.json")
    secret_store = LocalSecretStore(tmp_path / "epg-key.secret")
    settings.save({"iptv_password": "current-password", "http_port": 5140})
    secret_store.set_epg_key("current-key")
    monkeypatch.setattr(app_module, "settings_store", settings)
    monkeypatch.setattr(app_module, "epg_key_store", secret_store)

    client = app_module.app.test_client()
    backup = {
        "settings": {"http_port": 8787},
        "credentials": {"iptv_password": "restored-password", "epg_des3_key": "restored-key"},
    }

    settings_only = client.post("/api/backup/import", json={"backup": backup, "modules": ["settings"]})
    assert settings_only.status_code == 200
    assert settings.load()["http_port"] == 8787
    assert settings.load()["iptv_password"] == "current-password"
    assert secret_store.get_epg_key() == "current-key"

    restored = client.post("/api/backup/import", json={"backup": backup, "modules": ["credentials"]})
    assert restored.status_code == 200
    assert settings.load()["iptv_password"] == "restored-password"
    assert secret_store.get_epg_key() == "restored-key"


def test_legacy_backup_with_credentials_is_migrated_but_not_restored_implicitly(tmp_path, monkeypatch):
    settings = SettingsStore(tmp_path / "settings.json")
    secret_store = LocalSecretStore(tmp_path / "epg-key.secret")
    settings.save({"iptv_password": "current-password", "http_port": 5140})
    secret_store.set_epg_key("current-key")
    monkeypatch.setattr(app_module, "settings_store", settings)
    monkeypatch.setattr(app_module, "epg_key_store", secret_store)
    client = app_module.app.test_client()
    legacy = {
        "_version": 1,
        "settings": {
            "http_port": 6000,
            "iptv_password": "legacy-password",
            "epg_des3_key": "legacy-key",
        },
    }

    inspection = client.post("/api/backup/inspect", json={"backup": legacy})
    assert inspection.headers["Cache-Control"] == "no-store, max-age=0"
    normalized = inspection.get_json()["data"]["backup"]
    assert normalized["schema_version"] == 1
    assert normalized["_legacy_credentials_migrated"] is True
    assert normalized["credentials"] == {
        "iptv_password": "legacy-password",
        "epg_des3_key": "legacy-key",
    }
    assert "iptv_password" not in normalized["settings"]
    assert "epg_des3_key" not in normalized["settings"]

    restored_settings = client.post("/api/backup/import", json={"backup": legacy, "modules": ["settings"]})
    assert restored_settings.status_code == 200
    assert settings.load()["http_port"] == 6000
    assert settings.load()["iptv_password"] == "current-password"
    assert secret_store.get_epg_key() == "current-key"

    restored_credentials = client.post("/api/backup/import", json={"backup": legacy, "modules": ["credentials"]})
    assert restored_credentials.status_code == 200
    assert settings.load()["iptv_password"] == "legacy-password"
    assert secret_store.get_epg_key() == "legacy-key"


def test_legacy_backup_without_credentials_preserves_current_values(tmp_path, monkeypatch):
    settings = SettingsStore(tmp_path / "settings.json")
    secret_store = LocalSecretStore(tmp_path / "epg-key.secret")
    settings.save({"iptv_password": "current-password", "http_port": 5140})
    secret_store.set_epg_key("current-key")
    monkeypatch.setattr(app_module, "settings_store", settings)
    monkeypatch.setattr(app_module, "epg_key_store", secret_store)
    client = app_module.app.test_client()
    legacy = {"_version": 1, "settings": {"http_port": 6001}}

    inspection = client.post("/api/backup/inspect", json={"backup": legacy}).get_json()["data"]
    assert "credentials" not in inspection["available"]
    restored = client.post("/api/backup/import", json={"backup": legacy, "modules": ["settings"]})

    assert restored.status_code == 200
    assert settings.load()["http_port"] == 6001
    assert settings.load()["iptv_password"] == "current-password"
    assert secret_store.get_epg_key() == "current-key"


def test_v2_settings_only_backup_preserves_current_credentials(tmp_path, monkeypatch):
    settings = SettingsStore(tmp_path / "settings.json")
    secret_store = LocalSecretStore(tmp_path / "epg-key.secret")
    settings.save({"iptv_password": "current-password", "http_port": 5140})
    secret_store.set_epg_key("current-key")
    monkeypatch.setattr(app_module, "settings_store", settings)
    monkeypatch.setattr(app_module, "epg_key_store", secret_store)
    client = app_module.app.test_client()
    backup = {"schema_version": 2, "_version": 2, "settings": {"http_port": 6002}}

    restored = client.post("/api/backup/import", json={"backup": backup, "modules": ["settings"]})

    assert restored.status_code == 200
    assert restored.get_json()["data"]["warnings"]
    assert settings.load()["http_port"] == 6002
    assert settings.load()["iptv_password"] == "current-password"
    assert secret_store.get_epg_key() == "current-key"


def test_catchup_backup_restores_all_operator_fields_and_requires_refresh(tmp_path, monkeypatch):
    settings_path = tmp_path / "settings.json"
    operator_path = tmp_path / "operator_channels.json"
    settings = SettingsStore(settings_path)
    operators = OperatorChannelStore(operator_path)
    monkeypatch.setattr(app_module, "settings_store", settings)
    monkeypatch.setattr(app_module, "operator_channel_store", operators)
    monkeypatch.setattr(app_module, "_BACKUP_FILES", [
        ("settings", settings_path),
        ("operator_channels", operator_path),
    ])
    operator_record = {
        "key": "239.1.2.3:5000",
        "host": "239.1.2.3",
        "port": 5000,
        "name": "News",
        "channel_num": 1,
        "is_hd": True,
        "time_shift": True,
        "time_shift_minutes": 10080,
        "category": "其它频道",
        "operator_group": "新闻",
        "fcc_ip": "10.0.0.1",
        "fcc_port": 9000,
        "fec_port": 9001,
        "channel_id": "1001",
        "backtv_url": "rtsp://10.0.0.5/private?token=temporary",
        "source": "operator_channel_list",
    }
    backup = {
        "schema_version": 2,
        "settings": {
            "catchup_enabled": True,
            "catchup_days": 7,
            "catchup_auto_refresh_enabled": True,
            "catchup_auto_refresh_hours": 12,
            "timeshift_host": "10.0.0.5",
            "catchup_source_mode": "aptv",
            "catchup_source_template": "",
        },
        "operator_channels": {operator_record["key"]: operator_record},
    }

    response = app_module.app.test_client().post("/api/backup/import", json={
        "backup": backup,
        "modules": ["settings", "operator_channels"],
    })
    data = response.get_json()["data"]

    assert response.status_code == 200
    assert data["catchup_refresh_required"] is True
    assert any("Token" in warning for warning in data["warnings"])
    assert not any("部分回看数据" in warning for warning in data["warnings"])
    assert settings.load()["timeshift_host"] == "10.0.0.5"
    assert operators.load()[operator_record["key"]] == operator_record


def test_credential_restore_error_never_echoes_secret(tmp_path, monkeypatch):
    secret_value = "do-not-log-this-secret"
    logger = AppLogger(tmp_path / "app.log")

    class FailingSettingsStore(SettingsStore):
        def save(self, data):
            raise ValueError(f"failed while handling {secret_value}")

    monkeypatch.setattr(app_module, "settings_store", FailingSettingsStore(tmp_path / "settings.json"))
    monkeypatch.setattr(app_module, "epg_key_store", LocalSecretStore(tmp_path / "epg-key.secret"))
    monkeypatch.setattr(app_module, "logger", logger)
    response = app_module.app.test_client().post("/api/backup/import", json={
        "backup": {"schema_version": 2, "credentials": {"iptv_password": secret_value}},
        "modules": ["credentials"],
    })

    assert response.status_code == 200
    assert secret_value not in response.get_data(as_text=True)
    assert secret_value not in (tmp_path / "app.log").read_text(encoding="utf-8")


def test_management_page_disables_credential_autofill_and_has_no_test_port_instruction():
    page = app_module.app.test_client().get("/").get_data(as_text=True)

    assert 'id="iptvPassword" type="text" autocomplete="off"' in page
    assert 'id="epgDes3Key" type="text" autocomplete="off"' in page
    assert "请在 8788 设置页面" not in page
    assert 'id="backupExportAll"' in page
    assert 'id="disasterBackupExportBtn"' not in page
    assert 'id="disasterBackupImportBtn"' not in page
    assert 'id="stbDiscoveryArchiveSummary"' in page
    assert 'id="stbDiscoveryArchiveDeleteBtn"' in page


def test_subscription_copy_uses_page_status_without_prompt_fallback():
    script = (Path(app_module.app.static_folder) / "app.js").read_text(encoding="utf-8")

    assert '$("subscriptionCopyStatus")' in script
    assert "已复制${labels[key]" in script
    assert "prompt(" not in script


def test_dangerous_actions_use_double_dialogs_without_typed_confirmation():
    script = (Path(app_module.app.static_folder) / "app.js").read_text(encoding="utf-8")
    page = app_module.app.test_client().get("/").get_data(as_text=True)

    assert "function confirmTwice" in script
    assert script.count("confirmTwice(") >= 8
    assert "prompt(" not in script
    assert "执行确认文本" not in page
    assert "恢复确认文本" not in page
    assert "解除确认文本" not in page
    assert "开启确认文本" not in page
