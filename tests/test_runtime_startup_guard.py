from __future__ import annotations

import sys
from pathlib import Path

import windows_local_mcp.control_plane_guard as control_plane_guard


def test_runtime_startup_state_detects_missing_path_creation(tmp_path: Path) -> None:
    startup_archive = tmp_path / f"python{sys.version_info.major}{sys.version_info.minor}.zip"

    before = control_plane_guard._capture_runtime_startup_state([startup_archive])
    startup_archive.write_bytes(b"runtime shadow archive")
    after = control_plane_guard._capture_runtime_startup_state([startup_archive])

    assert before["digest"] != after["digest"]


def test_runtime_startup_state_detects_existing_override_content_change(
    tmp_path: Path,
) -> None:
    override = tmp_path / f"python{sys.version_info.major}{sys.version_info.minor}._pth"
    override.write_text("trusted-runtime\n", encoding="utf-8")

    before = control_plane_guard._capture_runtime_startup_state([override])
    override.write_text("malicious-runtime\nimport site\n", encoding="utf-8")
    after = control_plane_guard._capture_runtime_startup_state([override])

    assert before["digest"] != after["digest"]


def test_runtime_startup_candidates_include_executable_override_names() -> None:
    executable_directory = Path(sys.executable).resolve(strict=True).parent
    version_stem = f"python{sys.version_info.major}{sys.version_info.minor}"
    candidates = set(control_plane_guard._runtime_startup_candidate_paths())

    assert executable_directory / "python._pth" in candidates
    assert executable_directory / f"{version_stem}._pth" in candidates
    assert executable_directory / f"{version_stem}.zip" in candidates
