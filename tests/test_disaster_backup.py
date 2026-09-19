"""Complete disaster-recovery package tests."""

import hashlib
import io
import json
import stat
import zipfile
from types import SimpleNamespace

import app as app_module
from services.storage_service import LocalSecretStore, SettingsStore


def _configure_source(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    settings_path = source / "settings.json"
    channels_path = source / "channels.json"
    key_path = source / "epg-key.secret"
    settings = SettingsStore(settings_path)
    settings.save({
        "interface": "",
        "timeshift_host": "10.0.0.8:554",
        "iptv_password": "private-iptv-password",
    })
    channels_path.write_text(
        json.dumps({"239.1.1.1:8000": {"name": "CCTV1"}}), encoding="utf-8",
    )
    secret_store = LocalSecretStore(key_path)
    secret_store.set_epg_key("12345678")
    archives = source / "stb-captures"
    archives.mkdir()
    pcap = archives / "stb-boot-20260919-010203-000000001.pcap"
    pcap.write_bytes(b"pcap-private-payload")
    manifest_dir = archives / f"{pcap.stem}.artifacts"
    manifest_dir.mkdir()
    (manifest_dir / "manifest.json").write_text(
        json.dumps({"schema_version": 1, "source_pcap": pcap.name}), encoding="utf-8",
    )
    monkeypatch.setattr(app_module, "DATA_DIR", source)
    monkeypatch.setattr(app_module, "settings_store", settings)
    monkeypatch.setattr(app_module, "epg_key_store", secret_store)
    monkeypatch.setattr(app_module, "_BACKUP_FILES", [
        ("settings", settings_path),
        ("channels", channels_path),
    ])
    monkeypatch.setattr(app_module, "stb_discovery_service", SimpleNamespace(archive_dir=archives))
    return source, archives


def _export_bundle(client):
    response = client.post(
        "/api/backup/disaster-export",
        json={
            "confirmed": True,
            "modules": ["settings", "channels", "credentials", "pcap_archives"],
        },
    )
    assert response.status_code == 200
    bundle = response.get_data()
    response.close()
    return bundle


def test_complete_disaster_export_contains_credentials_pcaps_manifest_and_checksums(tmp_path, monkeypatch):
    source, _ = _configure_source(tmp_path, monkeypatch)
    client = app_module.app.test_client()

    denied = client.post("/api/backup/disaster-export", json={"modules": ["pcap_archives"]})
    assert denied.status_code == 400

    bundle = _export_bundle(client)
    assert list(source.glob(".iptv-disaster-*.zip")) == []
    with zipfile.ZipFile(io.BytesIO(bundle)) as zf:
        names = set(zf.namelist())
        assert {"backup.json", "deployment.json", "README.txt", "CHECKSUMS.sha256"}.issubset(names)
        assert "pcaps/stb-boot-20260919-010203-000000001.pcap" in names
        assert "metadata/stb-boot-20260919-010203-000000001.manifest.json" in names
        backup = json.loads(zf.read("backup.json"))
        assert backup["credentials"] == {
            "iptv_password": "private-iptv-password",
            "epg_des3_key": "12345678",
        }
        assert backup["settings"]["timeshift_host"] == "10.0.0.8:554"
        checksums = zf.read("CHECKSUMS.sha256").decode("utf-8")
        assert hashlib.sha256(zf.read("backup.json")).hexdigest() in checksums
        assert hashlib.sha256(zf.read("pcaps/stb-boot-20260919-010203-000000001.pcap")).hexdigest() in checksums


def test_migration_zip_honors_selected_modules(tmp_path, monkeypatch):
    _configure_source(tmp_path, monkeypatch)
    response = app_module.app.test_client().post(
        "/api/backup/disaster-export",
        json={
            "confirmed": True,
            "modules": ["settings", "pcap_archives"],
        },
    )
    assert response.status_code == 200
    bundle = response.get_data()
    response.close()
    with zipfile.ZipFile(io.BytesIO(bundle)) as zf:
        backup = json.loads(zf.read("backup.json"))
        assert "settings" in backup
        assert "channels" not in backup
        assert "credentials" not in backup
        assert any(name.startswith("pcaps/") for name in zf.namelist())


def test_complete_disaster_restore_into_fresh_data_directory(tmp_path, monkeypatch):
    _configure_source(tmp_path, monkeypatch)
    client = app_module.app.test_client()
    bundle = _export_bundle(client)

    target = tmp_path / "target"
    target.mkdir()
    settings_path = target / "settings.json"
    channels_path = target / "channels.json"
    key_path = target / "epg-key.secret"
    archives = target / "stb-captures"
    target_settings = SettingsStore(settings_path)
    monkeypatch.setattr(app_module, "settings_store", target_settings)
    monkeypatch.setattr(app_module, "epg_key_store", LocalSecretStore(key_path))
    monkeypatch.setattr(app_module, "_BACKUP_FILES", [
        ("settings", settings_path),
        ("channels", channels_path),
    ])
    monkeypatch.setattr(app_module, "stb_discovery_service", SimpleNamespace(archive_dir=archives))

    response = client.post(
        "/api/backup/disaster-import",
        data={
            "confirmed": "true",
            "file": (io.BytesIO(bundle), "complete.zip"),
        },
        content_type="multipart/form-data",
    )
    data = response.get_json()["data"]

    assert response.status_code == 200
    assert set(data["restored"]) == {"settings", "channels", "credentials"}
    assert data["pcap_archives_restored"] == 1
    assert data["protocol_manifests_restored"] == 1
    assert target_settings.load()["iptv_password"] == "private-iptv-password"
    assert target_settings.load()["timeshift_host"] == "10.0.0.8:554"
    assert LocalSecretStore(key_path).get_epg_key() == "12345678"
    restored_pcap = archives / "stb-boot-20260919-010203-000000001.pcap"
    restored_manifest = archives / "stb-boot-20260919-010203-000000001.artifacts" / "manifest.json"
    assert restored_pcap.read_bytes() == b"pcap-private-payload"
    assert json.loads(restored_manifest.read_text(encoding="utf-8"))["schema_version"] == 1
    assert stat.S_IMODE(restored_pcap.stat().st_mode) == 0o600
    assert stat.S_IMODE(restored_manifest.stat().st_mode) == 0o600
    assert stat.S_IMODE(archives.stat().st_mode) == 0o700


def test_disaster_restore_rejects_checksum_tampering_and_unsupported_paths(tmp_path, monkeypatch):
    _configure_source(tmp_path, monkeypatch)
    client = app_module.app.test_client()
    bundle = _export_bundle(client)

    tampered = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(bundle)) as source, zipfile.ZipFile(tampered, "w") as target:
        for name in source.namelist():
            content = source.read(name)
            if name == "backup.json":
                content += b" "
            target.writestr(name, content)
    response = client.post(
        "/api/backup/disaster-import",
        data={"confirmed": "true", "file": (io.BytesIO(tampered.getvalue()), "tampered.zip")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "校验失败" in response.get_json()["error"]

    traversal = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(bundle)) as source, zipfile.ZipFile(traversal, "w") as target:
        for name in source.namelist():
            target.writestr(name, source.read(name))
        target.writestr("../escape", b"no")
    response = client.post(
        "/api/backup/disaster-import",
        data={"confirmed": "true", "file": (io.BytesIO(traversal.getvalue()), "traversal.zip")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "不支持的路径" in response.get_json()["error"]
    assert not (tmp_path / "escape").exists()


def test_disaster_restore_refuses_different_existing_pcap_before_settings_change(tmp_path, monkeypatch):
    _configure_source(tmp_path, monkeypatch)
    client = app_module.app.test_client()
    bundle = _export_bundle(client)

    target = tmp_path / "conflict-target"
    archives = target / "stb-captures"
    archives.mkdir(parents=True)
    conflict = archives / "stb-boot-20260919-010203-000000001.pcap"
    conflict.write_bytes(b"different-capture")
    settings_path = target / "settings.json"
    settings = SettingsStore(settings_path)
    settings.save({"timeshift_host": "keep-this-value", "iptv_password": "keep-this-password"})
    key_store = LocalSecretStore(target / "epg-key.secret")
    key_store.set_epg_key("keep-key")
    monkeypatch.setattr(app_module, "settings_store", settings)
    monkeypatch.setattr(app_module, "epg_key_store", key_store)
    monkeypatch.setattr(app_module, "_BACKUP_FILES", [
        ("settings", settings_path),
        ("channels", target / "channels.json"),
    ])
    monkeypatch.setattr(app_module, "stb_discovery_service", SimpleNamespace(archive_dir=archives))

    response = client.post(
        "/api/backup/disaster-import",
        data={"confirmed": "true", "file": (io.BytesIO(bundle), "complete.zip")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 409
    assert conflict.read_bytes() == b"different-capture"
    assert settings.load()["timeshift_host"] == "keep-this-value"
    assert settings.load()["iptv_password"] == "keep-this-password"
    assert key_store.get_epg_key() == "keep-key"


def test_disaster_restore_requires_explicit_confirmation(tmp_path, monkeypatch):
    _configure_source(tmp_path, monkeypatch)
    client = app_module.app.test_client()
    bundle = _export_bundle(client)
    response = client.post(
        "/api/backup/disaster-import",
        data={"file": (io.BytesIO(bundle), "complete.zip")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
