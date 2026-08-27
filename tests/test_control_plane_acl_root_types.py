from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import windows_local_mcp.control_plane_guard as control_plane_guard


@pytest.mark.skipif(os.name != "nt", reason="icacls command shape is Windows-specific")
def test_acl_state_digest_recurses_directories_but_not_single_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "control-plane"
    directory.mkdir()
    (directory / "nested.txt").write_text("nested", encoding="utf-8")
    config = tmp_path / "config.toml"
    config.write_text("workspace_root = 'C:/workspace'", encoding="utf-8")

    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append((list(command), dict(kwargs)))
        return subprocess.CompletedProcess(command, 0, stdout=b"acl-state", stderr=b"")

    monkeypatch.setattr(
        control_plane_guard,
        "windows_system_executable",
        lambda name: f"C:/Windows/System32/{name}",
    )
    monkeypatch.setattr(control_plane_guard.subprocess, "run", fake_run)

    settings = SimpleNamespace(approval_manifest_max_bytes=1024 * 1024)
    digest, byte_count = control_plane_guard._acl_state_digest(  # noqa: SLF001
        settings,  # type: ignore[arg-type]
        [directory, config],
    )

    assert digest
    assert byte_count == len(b"acl-state") * 2
    assert calls[0][0] == [
        "C:/Windows/System32/icacls.exe",
        str(directory),
        "/T",
        "/C",
    ]
    assert calls[1][0] == [
        "C:/Windows/System32/icacls.exe",
        str(config),
        "/C",
    ]
    assert "/T" not in calls[1][0]
    for _, kwargs in calls:
        assert kwargs == {
            "capture_output": True,
            "timeout": 30,
            "check": False,
            "shell": False,
        }
