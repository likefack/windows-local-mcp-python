from __future__ import annotations

import json
from pathlib import Path

import pytest

from windows_local_mcp.approved_host_recovery import (
    inspect_postflight_recovery,
    quarantine_postflight_recovery,
)
from windows_local_mcp.config import Settings
from windows_local_mcp.control_plane_guard import assert_control_plane_healthy


def _settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        git_enabled=False,
    )
    settings.ensure_directories()
    (settings.data_dir / "control-plane").mkdir(parents=True, exist_ok=True)
    return settings


def _write_pending(settings: Settings, operation_id: str) -> Path:
    marker = settings.data_dir / "control-plane" / "approved-host-postflight-pending.json"
    marker.write_text(
        json.dumps(
            {
                "version": 1,
                "armed_at": "2026-08-28T00:00:00+00:00",
                "operation_id": operation_id,
                "state": "postflight_pending",
                "recovery": "manual operator review required",
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    return marker


def test_inspect_binds_pending_postflight_marker_to_operation(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    marker = _write_pending(settings, "operation-1")

    evidence = inspect_postflight_recovery(settings, "operation-1")

    assert evidence["present"] is True
    assert evidence["quarantined"] is False
    assert evidence["operation_id"] == "operation-1"
    assert evidence["marker_payload"]["operation_id"] == "operation-1"
    assert evidence["marker_identity"]["sha256"]
    assert marker.is_file()


def test_recovery_rejects_operation_binding_mismatch(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    marker = _write_pending(settings, "operation-1")

    with pytest.raises(RuntimeError, match="operation binding"):
        inspect_postflight_recovery(settings, "operation-2")

    assert marker.is_file()


def test_recovery_never_clears_independent_tamper_latch(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    marker = _write_pending(settings, "operation-1")
    tamper = settings.data_dir / "control-plane" / "tamper-detected.json"
    tamper.write_text('{"tamper":true}', encoding="utf-8")

    with pytest.raises(RuntimeError, match="tamper marker"):
        inspect_postflight_recovery(settings, "operation-1")

    assert marker.is_file()
    assert tamper.is_file()


def test_quarantine_requires_reviewed_digest_and_restores_health(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    marker = _write_pending(settings, "operation-1")
    evidence = inspect_postflight_recovery(settings, "operation-1")
    digest = str(evidence["marker_identity"]["sha256"])

    recovered = quarantine_postflight_recovery(
        settings,
        "operation-1",
        expected_sha256=digest,
    )

    assert recovered["quarantined"] is True
    assert recovered["resumed_partial_recovery"] is False
    assert not marker.exists()
    quarantine = Path(str(recovered["quarantine_path"]))
    assert quarantine.is_file()
    assert recovered["marker_identity"]["sha256"] == digest
    assert_control_plane_healthy(settings)


def test_quarantine_rejects_changed_review_digest_without_clearing(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    marker = _write_pending(settings, "operation-1")

    with pytest.raises(RuntimeError, match="changed after operator review"):
        quarantine_postflight_recovery(
            settings,
            "operation-1",
            expected_sha256="0" * 64,
        )

    assert marker.is_file()
    with pytest.raises(RuntimeError, match="postflight verification"):
        assert_control_plane_healthy(settings)


def test_interrupted_quarantine_is_detected_and_resumable(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    marker = _write_pending(settings, "operation-1")
    evidence = inspect_postflight_recovery(settings, "operation-1")
    digest = str(evidence["marker_identity"]["sha256"])
    quarantine = marker.with_name(
        f"approved-host-postflight-recovered-operation-1-{digest[:16]}.json"
    )
    marker.rename(quarantine)

    resumed_evidence = inspect_postflight_recovery(settings, "operation-1")
    assert resumed_evidence["present"] is False
    assert resumed_evidence["quarantined"] is True

    recovered = quarantine_postflight_recovery(
        settings,
        "operation-1",
        expected_sha256=digest,
    )
    assert recovered["resumed_partial_recovery"] is True
    assert recovered["quarantine_path"] == str(quarantine.resolve(strict=True))
    assert_control_plane_healthy(settings)
