import os
from hashlib import sha256
from pathlib import Path

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.tool_safety import (
    capture_executable_identity,
    hold_executable_identity,
    trusted_helper_identity,
    verify_executable_identity,
)


def make_settings(tmp_path: Path, executable: Path, digest: str) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        sandbox_scratch_dir=tmp_path / "scratch",
        protect_data_dir_acl=False,
        git_executable_path=executable,
        git_executable_sha256=digest,
    )
    settings.ensure_directories()
    return settings


def test_broker_helper_requires_matching_explicit_hash(tmp_path: Path) -> None:
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"trusted-git")
    digest = sha256(executable.read_bytes()).hexdigest()
    settings = make_settings(tmp_path, executable, digest)

    identity = trusted_helper_identity(settings, "git")
    assert identity["path"] == str(executable.resolve())
    assert identity["sha256"] == digest
    assert identity["provenance"] == "explicit-local-config"
    stable_identity = identity["stable_file_identity"]
    assert stable_identity["platform"] == ("windows" if os.name == "nt" else "posix")
    if os.name == "nt":
        assert stable_identity["volume_serial_number"] >= 0
        assert stable_identity["file_index"] > 0

    settings.git_executable_sha256 = "0" * 64
    with pytest.raises(PermissionError, match="SHA-256"):
        trusted_helper_identity(settings, "git")


def test_stale_executable_identity_is_rejected(tmp_path: Path) -> None:
    executable = tmp_path / "helper.exe"
    executable.write_bytes(b"first")
    identity = capture_executable_identity(
        executable, provenance="test-approval"
    )
    replacement = tmp_path / "replacement.exe"
    replacement.write_bytes(b"second")
    os.replace(replacement, executable)

    with pytest.raises((PermissionError, RuntimeError), match="executable|SHA-256"):
        verify_executable_identity(identity)


@pytest.mark.skipif(os.name != "nt", reason="Windows file-sharing semantics")
def test_windows_executable_hold_denies_replacement_until_release(tmp_path: Path) -> None:
    trusted_directory = tmp_path / "trusted" / "bin"
    trusted_directory.mkdir(parents=True)
    executable = trusted_directory / "held.exe"
    executable.write_bytes(b"held")
    identity = capture_executable_identity(executable, provenance="live-test")
    replacement = tmp_path / "replacement.exe"
    replacement.write_bytes(b"replacement")
    renamed_directory = tmp_path / "renamed-trusted"

    with hold_executable_identity(identity):
        with pytest.raises(OSError):
            os.replace(replacement, executable)
        with pytest.raises(OSError):
            os.replace(trusted_directory.parent, renamed_directory)

    os.replace(replacement, executable)
    assert executable.read_bytes() == b"replacement"
    os.replace(trusted_directory.parent, renamed_directory)
    assert (renamed_directory / "bin" / "held.exe").is_file()
