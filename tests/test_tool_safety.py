import os
from hashlib import sha256
from pathlib import Path

import pytest

from windows_local_mcp.config import Settings
from windows_local_mcp.git_broker_sandbox import GitBrokerUnavailable
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


def test_automatic_git_broker_helper_requires_git_specific_live_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"trusted-git")
    digest = sha256(executable.read_bytes()).hexdigest()
    settings = make_settings(tmp_path, executable, digest)

    from windows_local_mcp import git_broker_live_verify

    monkeypatch.setattr(
        git_broker_live_verify,
        "require_git_broker_live_verification",
        lambda _settings, _identity: (_ for _ in ()).throw(
            GitBrokerUnavailable("Git-specific live verification is missing")
        ),
    )
    with pytest.raises(GitBrokerUnavailable, match="Git-specific live verification is missing"):
        trusted_helper_identity(settings, "git")


def test_automatic_git_broker_helper_accepts_pinned_git_after_live_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "git.exe"
    executable.write_bytes(b"trusted-git")
    digest = sha256(executable.read_bytes()).hexdigest()
    settings = make_settings(tmp_path, executable, digest)

    from windows_local_mcp import git_broker_live_verify

    observed: dict[str, object] = {}

    def verified(_settings: Settings, identity: dict[str, object]) -> dict[str, object]:
        observed.update(identity)
        return {"version": 1, "context_digest": "test"}

    monkeypatch.setattr(
        git_broker_live_verify, "require_git_broker_live_verification", verified
    )
    identity = trusted_helper_identity(settings, "git")

    assert identity["path"] == str(executable.resolve())
    assert identity["sha256"] == digest
    assert observed["sha256"] == digest


def test_adb_broker_helper_requires_matching_explicit_hash(tmp_path: Path) -> None:
    executable = tmp_path / "adb.exe"
    executable.write_bytes(b"trusted-adb")
    digest = sha256(executable.read_bytes()).hexdigest()
    settings = make_settings(tmp_path, executable, digest)
    settings.adb_executable_path = executable
    settings.adb_executable_sha256 = digest

    identity = trusted_helper_identity(settings, "adb")
    assert identity["path"] == str(executable.resolve())
    assert identity["sha256"] == digest
    assert identity["provenance"] == "explicit-local-config"
    stable_identity = identity["stable_file_identity"]
    assert stable_identity["platform"] == ("windows" if os.name == "nt" else "posix")
    if os.name == "nt":
        assert stable_identity["volume_serial_number"] >= 0
        assert stable_identity["file_index"] > 0

    settings.adb_executable_sha256 = "0" * 64
    with pytest.raises(PermissionError, match="SHA-256"):
        trusted_helper_identity(settings, "adb")


def test_stale_executable_identity_is_rejected(tmp_path: Path) -> None:
    executable = tmp_path / "helper.exe"
    executable.write_bytes(b"first")
    identity = capture_executable_identity(executable, provenance="test-approval")
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
