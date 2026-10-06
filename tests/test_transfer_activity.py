from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from windows_local_mcp import transfer_activity
from windows_local_mcp.config import Settings
from windows_local_mcp.resources import NamedControlPlaneLock
from windows_local_mcp.transfer_activity import (
    TransferActivityState,
    read_transfer_activity_state,
)

TRANSFER_ID = "fe6365dc-ccfb-41df-9115-3978a65da1e7"
OPERATION_ID = "b3ef0e04-fac6-41ee-894b-f039a09c2410"
NOW = datetime(2026, 10, 6, 12, tzinfo=UTC)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    # 表示用の読み取り試験では、runtime 初期化や実環境の設定検査は行わない。
    return Settings.model_construct(
        workspace_root=tmp_path / "workspace", data_dir=tmp_path / "data",
        binary_transfer_ttl_seconds=1800,
    )


def _write_manifest(settings: Settings, **overrides: Any) -> Path:
    path = settings.data_dir / "binary-transfers" / TRANSFER_ID / "manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "version": 5, "direction": "upload", "operation_id": OPERATION_ID,
        "state": "open", "created_at": (NOW - timedelta(minutes=5)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
    }
    manifest.update(overrides)
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def _read(settings: Settings, **overrides: Any) -> TransferActivityState:
    arguments = {
        "transfer_id": TRANSFER_ID, "operation_id": OPERATION_ID,
        "direction": "upload", "now": NOW,
    }
    arguments.update(overrides)
    return read_transfer_activity_state(settings, **arguments)


@pytest.mark.parametrize("version", [1, 2, 3, 4, 5])
@pytest.mark.parametrize("state", ["preparing", "open"])
@pytest.mark.parametrize("direction", ["download", "upload"])
def test_active_manifest_versions(
    settings: Settings, version: int, state: str, direction: str,
) -> None:
    _write_manifest(settings, version=version, state=state, direction=direction)
    assert _read(settings, direction=direction) == TransferActivityState(state)


@pytest.mark.parametrize("state", ["completed", "committed", "cancelled", "expired", "failed"])
def test_terminal_state_and_its_own_timestamp_survive_expiry(
    settings: Settings, state: str,
) -> None:
    finished = (NOW - timedelta(minutes=2)).isoformat()
    _write_manifest(
        settings, state=state, expires_at=(NOW - timedelta(minutes=1)).isoformat(),
        **{f"{state}_at": finished},
    )
    assert _read(settings) == TransferActivityState(state, finished)


@pytest.mark.parametrize("value", [None, 7, "invalid", "2026-10-06T11:59:00"])
def test_invalid_optional_terminal_timestamp_is_not_displayed(
    settings: Settings, value: object,
) -> None:
    _write_manifest(settings, state="cancelled", cancelled_at=value, completed_at=NOW.isoformat())
    assert _read(settings) == TransferActivityState("cancelled")


def test_terminal_timestamp_is_normalized(settings: Settings) -> None:
    _write_manifest(settings, state="completed", completed_at="2026-10-06T11:59:00Z")
    assert _read(settings) == TransferActivityState("completed", "2026-10-06T11:59:00+00:00")


@pytest.mark.parametrize("state", ["preparing", "open"])
def test_expiry_boundary_and_absolute_lifetime(settings: Settings, state: str) -> None:
    expiry = NOW - timedelta(seconds=1)
    _write_manifest(settings, state=state, expires_at=expiry.isoformat())
    # 設定上の TTL ではまだ有効でも、保存済みの絶対期限を優先する。
    assert _read(settings, now=expiry) == TransferActivityState(state)
    assert _read(settings) == TransferActivityState("expired", expiry.isoformat())


def test_legacy_expiry_uses_transfer_ttl(settings: Settings) -> None:
    created = NOW - timedelta(seconds=settings.binary_transfer_ttl_seconds)
    path = _write_manifest(settings, version=1, created_at=created.isoformat())
    manifest = json.loads(path.read_text(encoding="utf-8"))
    del manifest["expires_at"]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    assert _read(settings) == TransferActivityState("open")
    assert _read(settings, now=NOW + timedelta(microseconds=1)) == TransferActivityState(
        "expired", NOW.isoformat(),
    )


@pytest.mark.parametrize("field,value", [
    ("version", 0), ("version", 6), ("version", True), ("version", 1.0),
    ("version", "5"), ("operation_id", TRANSFER_ID), ("operation_id", None),
    ("direction", "download"), ("direction", None), ("state", "unknown"),
    ("state", None), ("state", []), ("created_at", None),
    ("created_at", "2026-10-06T11:55:00"), ("expires_at", None),
    ("expires_at", "invalid"), ("expires_at", "2026-10-06T12:05:00"),
    ("expires_at", "2026-10-06T11:00:00+00:00"),
])
def test_invalid_manifest_is_unavailable(settings: Settings, field: str, value: object) -> None:
    _write_manifest(settings, **{field: value})
    assert _read(settings) == TransferActivityState("unavailable")


@pytest.mark.parametrize("field", ["version", "operation_id", "direction", "state", "created_at"])
def test_required_manifest_fields(settings: Settings, field: str) -> None:
    path = _write_manifest(settings)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    del manifest[field]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    assert _read(settings) == TransferActivityState("unavailable")


@pytest.mark.parametrize("field,value", [
    ("transfer_id", "../manifest"), ("transfer_id", "..\\manifest"),
    ("transfer_id", "C:\\outside"), ("transfer_id", TRANSFER_ID.upper()),
    ("transfer_id", TRANSFER_ID.replace("-", "")), ("transfer_id", "{" + TRANSFER_ID + "}"),
    ("transfer_id", "-" * 36), ("transfer_id", None),
    ("operation_id", "invalid"), ("operation_id", OPERATION_ID.upper()),
    ("direction", "invalid"), ("direction", []), ("now", NOW.replace(tzinfo=None)),
])
def test_invalid_input_is_rejected_before_lock_or_read(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, field: str, value: object,
) -> None:
    def unexpected(*_args: object, **_kwargs: object) -> None:
        pytest.fail("invalid input must not create a lock or read a path")

    monkeypatch.setattr(transfer_activity, "NamedControlPlaneLock", unexpected)
    monkeypatch.setattr(transfer_activity, "read_verified_path_bytes", unexpected)
    assert _read(settings, **{field: value}) == TransferActivityState("unavailable")
    assert not settings.data_dir.exists()


@pytest.mark.parametrize("payload", [
    b"not-json", b"[]", b"null", b"\xff",
    pytest.param(b"[" * 5000, id="deeply-nested-json"),
])
def test_malformed_manifest(settings: Settings, payload: bytes) -> None:
    path = _write_manifest(settings)
    path.write_bytes(payload)
    assert _read(settings) == TransferActivityState("unavailable")


def test_manifest_byte_limit(settings: Settings) -> None:
    path = _write_manifest(settings)
    content = path.read_bytes()
    path.write_bytes(content + b" " * (64 * 1024 - len(content)))
    assert _read(settings) == TransferActivityState("open")
    with path.open("ab") as output:
        output.write(b" ")
    assert _read(settings) == TransferActivityState("unavailable")


def test_missing_manifest(settings: Settings) -> None:
    assert _read(settings) == TransferActivityState("unavailable")


def test_read_failure_does_not_expose_details(
    settings: Settings, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_manifest(settings)

    def fail(*_args: object, **_kwargs: object) -> bytes:
        raise PermissionError("secret path or content must not reach the display")

    monkeypatch.setattr(transfer_activity, "read_verified_path_bytes", fail)
    assert _read(settings) == TransferActivityState("unavailable")


def test_display_does_not_modify_manifest_payload_or_audit(settings: Settings) -> None:
    path = _write_manifest(settings, expires_at=(NOW - timedelta(seconds=1)).isoformat())
    payload = path.parent / "payload.bin"
    payload.write_bytes(b"private payload")
    audit = settings.data_dir / "audit.db"
    audit.write_bytes(b"audit sentinel")
    paths = [path, payload, audit]
    before = [(item.read_bytes(), item.stat().st_mtime_ns) for item in paths]
    assert _read(settings).state == "expired"
    assert [(item.read_bytes(), item.stat().st_mtime_ns) for item in paths] == before


def test_reader_releases_verified_handles_before_writer_replace(settings: Settings) -> None:
    path = _write_manifest(settings)
    assert _read(settings).state == "open"
    replacement = path.with_name("replacement.json")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["state"] = "cancelled"
    replacement.write_text(json.dumps(manifest), encoding="utf-8")
    with NamedControlPlaneLock(settings, f"transfer-{TRANSFER_ID}"):
        replacement.replace(path)
    assert _read(settings).state == "cancelled"


def test_writer_lock_contention_is_unavailable_without_reading(
    settings: Settings, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_manifest(settings)
    acquired = threading.Event()
    release = threading.Event()
    errors: list[Exception] = []

    def writer() -> None:
        try:
            with NamedControlPlaneLock(settings, f"transfer-{TRANSFER_ID}"):
                acquired.set()
                if not release.wait(2):
                    raise TimeoutError("test writer was not released")
        except Exception as error:  # noqa: BLE001 - 別スレッドの失敗も主スレッドで検証する。
            errors.append(error)
            acquired.set()

    def unexpected(*_args: object, **_kwargs: object) -> bytes:
        pytest.fail("a contended display must not read the writer's manifest")

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    try:
        assert acquired.wait(2)
        assert not errors
        monkeypatch.setattr(transfer_activity, "read_verified_path_bytes", unexpected)
        assert _read(settings) == TransferActivityState("unavailable")
    finally:
        release.set()
        thread.join(timeout=2)
    assert not thread.is_alive()
    assert not errors


def test_hardlinked_manifest_is_unavailable(settings: Settings) -> None:
    path = _write_manifest(settings)
    duplicate = path.with_name("duplicate.json")
    try:
        duplicate.hardlink_to(path)
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")
    assert _read(settings) == TransferActivityState("unavailable")


@pytest.mark.parametrize("link_directory", [False, True])
def test_linked_manifest_path_is_unavailable(
    settings: Settings, tmp_path: Path, link_directory: bool,
) -> None:
    path = _write_manifest(settings)
    source = tmp_path / "original"
    try:
        if link_directory:
            path.parent.rename(source)
            path.parent.symlink_to(source, target_is_directory=True)
        else:
            path.rename(source)
            path.symlink_to(source)
    except OSError:
        pytest.skip("creating symlinks requires Windows developer mode or elevation")
    assert _read(settings) == TransferActivityState("unavailable")
