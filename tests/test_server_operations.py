import importlib
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from windows_local_mcp.sandbox_backend import CodexSandboxBackend
from windows_local_mcp.util import sha256_bytes


def load_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "workspace"
    root.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{str(root).replace(chr(92), chr(92) * 2)}"',
                f'data_dir = "{str(data).replace(chr(92), chr(92) * 2)}"',
                "protect_data_dir_acl = false",
                "git_enabled = false",
                "max_write_bytes = 4096",
                "max_diff_bytes = 8192",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    sys.modules.pop("windows_local_mcp.server", None)
    server = importlib.import_module("windows_local_mcp.server")
    return server, root


def test_concurrent_write_with_same_expected_hash_has_one_winner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    target = root / "shared.txt"
    target.write_text("initial", encoding="utf-8")
    expected = sha256_bytes(b"initial")

    def write(value: str) -> str:
        try:
            server.write_file("shared.txt", value, expected_sha256=expected)
            return "succeeded"
        except RuntimeError as error:
            assert "expected_sha256 mismatch" in str(error)
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(write, ["first", "second"]))
    assert sorted(results) == ["conflict", "succeeded"]
    assert target.read_text(encoding="utf-8") in {"first", "second"}


def test_crlf_read_identity_is_the_raw_commit_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    target = root / "windows.txt"
    target.write_bytes(b"first\r\nsecond\r\n")

    inspected = server.read_file("windows.txt")
    assert inspected["sha256"] == sha256_bytes(b"first\r\nsecond\r\n")
    assert inspected["newline"] == "crlf"
    result = server.write_file(
        "windows.txt",
        "changed\r\n",
        expected_sha256=inspected["sha256"],
    )
    assert result["before_sha256"] == inspected["sha256"]
    assert target.read_bytes() == b"changed\r\n"


def test_write_file_uses_a_target_scoped_execution_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    real_lock = server.WorkspaceExecutionLock
    locked_targets: list[tuple[Path, ...] | None] = []

    class RecordingLock:
        def __init__(self, settings, timeout=30.0, *, target=None, targets=None):
            selected = tuple(targets) if targets is not None else ((target,) if target else None)
            locked_targets.append(selected)
            self._lock = real_lock(settings, timeout, target=target, targets=targets)

        def __enter__(self):
            return self._lock.__enter__()

        def __exit__(self, *args):
            return self._lock.__exit__(*args)

    monkeypatch.setattr(server, "WorkspaceExecutionLock", RecordingLock)
    server.write_file("scoped.txt", "bounded mutation")

    assert locked_targets == [((root / "scoped.txt").resolve(),)]


def test_oversized_write_is_rejected_and_audited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _ = load_server(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="max_write_bytes"):
        server.write_file("large.txt", "x" * 5000)
    records = server.runtime.audit.list_operations(limit=10)
    assert any(
        record["tool_name"] == "write_file" and record["status"] == "rejected"
        for record in records
    )


def test_denied_command_is_audited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    server, _ = load_server(tmp_path, monkeypatch)
    with pytest.raises(PermissionError):
        server.execute_readonly("python", ["-c", "print(1)"])
    records = server.runtime.audit.list_operations(limit=10)
    assert any(
        record["tool_name"] == "execute_readonly" and record["status"] == "rejected"
        for record in records
    )


def test_git_info_failure_terminalizes_its_operation_without_duplicate_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _ = load_server(tmp_path, monkeypatch)
    server.runtime.settings.git_enabled = True
    monkeypatch.setattr(
        server,
        "capture_git_snapshot",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("snapshot failed")),
    )

    with pytest.raises(RuntimeError, match="snapshot failed"):
        server.git_info()

    records = [
        record
        for record in server.runtime.audit.list_operations(limit=20)
        if record["tool_name"] == "git_info"
    ]
    assert len(records) == 1
    assert records[0]["status"] == "failed"
    assert records[0]["id"] not in {
        operation["id"] for operation in server.runtime.audit.list_active_operations()
    }
    timeline_record = next(
        item
        for item in server.activity_timeline()
        if item["operation_id"] == records[0]["id"]
    )
    assert timeline_record["status"] == "failed"


def test_approved_sandbox_and_host_are_distinct_requests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _ = load_server(tmp_path, monkeypatch)
    codex = tmp_path / "trusted" / "codex.exe"
    codex.parent.mkdir()
    codex.write_bytes(b"fake installed codex")
    backend = CodexSandboxBackend(
        executable=str(codex.resolve()),
        executable_sha256="a" * 64,
        executable_size=codex.stat().st_size,
        executable_mtime_ns=codex.stat().st_mtime_ns,
        windows_mode="elevated",
        permission_profile=":workspace",
        provenance="mock",
        signature_status="Valid",
        signer_subject="OpenAI",
        signer_thumbprint="b" * 40,
        helpers=(),
    )
    monkeypatch.setattr(server, "resolve_codex_sandbox_backend", lambda _settings: backend)
    monkeypatch.setattr(
        server,
        "require_codex_sandbox_live_verification",
        lambda _settings, _backend: {"version": 2, "passed": True},
    )

    sandbox = server.request_sandbox_command(
        [sys.executable, "-c", "print('sandbox')"],
        reason="run broad developer command in approved sandbox",
    )
    sandbox_record = server.runtime.audit.get_operation(sandbox["approval_id"])
    assert sandbox_record["tier"] == "codex_sandbox"
    assert sandbox_record["request"]["sandbox_backend"]["authentication_required"] is False
    assert sandbox_record["request"]["effective_sandbox_policy"]["network_policy"][
        "internet"
    ] == "deny"

    host = server.request_host_command(
        [sys.executable, "-c", "print('host')"],
        reason="explicit host-only operation",
    )
    host_record = server.runtime.audit.get_operation(host["approval_id"])
    assert host_record["tier"] == "approved_host"
    assert host_record["request"]["sandbox_backend"] is None


def test_sandbox_dependency_availability_is_separate_from_live_verified_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _ = load_server(tmp_path, monkeypatch)
    codex = tmp_path / "trusted" / "codex.exe"
    codex.parent.mkdir()
    codex.write_bytes(b"fake installed codex")
    backend = CodexSandboxBackend(
        executable=str(codex.resolve()),
        executable_sha256="a" * 64,
        executable_size=codex.stat().st_size,
        executable_mtime_ns=codex.stat().st_mtime_ns,
        windows_mode="elevated",
        permission_profile=":workspace",
        provenance="mock",
        signature_status="Valid",
        signer_subject="OpenAI",
        signer_thumbprint="b" * 40,
        helpers=(),
    )
    monkeypatch.setattr(server, "resolve_codex_sandbox_backend", lambda _settings: backend)
    monkeypatch.setattr(
        server,
        "require_codex_sandbox_live_verification",
        lambda _settings, _backend: (_ for _ in ()).throw(
            RuntimeError("property evidence is incomplete")
        ),
    )

    status = server._codex_sandbox_capability()

    assert status["dependency_available"] is True
    assert status["available"] is True
    assert status["execution_route_available"] is False
    assert status["windows_live_verified"] is False
    assert "property evidence is incomplete" in status["execution_unavailable_reason"]


def test_approved_host_capability_does_not_preflight_when_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _ = load_server(tmp_path, monkeypatch)
    server.runtime.settings.approved_host_enabled = False

    def unexpected_preflight():
        raise AssertionError("disabled Approved Host must not run runtime preflight")

    monkeypatch.setattr(server, "assert_approved_host_runtime_immutable", unexpected_preflight)

    status = server._approved_host_capability()

    assert status["enabled"] is False
    assert status["available"] is False
    assert status["runtime_preflight"]["status"] == "not_run"


def test_approved_host_capability_reports_failed_runtime_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _ = load_server(tmp_path, monkeypatch)
    server.runtime.settings.approved_host_enabled = True
    monkeypatch.setattr(
        server,
        "assert_approved_host_runtime_immutable",
        lambda: (_ for _ in ()).throw(RuntimeError("runtime is mutable")),
    )

    status = server._approved_host_capability()

    assert status["enabled"] is True
    assert status["available"] is False
    assert status["runtime_preflight"]["status"] == "failed"
    assert "runtime is mutable" in status["runtime_preflight"]["error"]
    assert status["execution_time_recheck"] is True


def test_approved_host_capability_reports_passed_runtime_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _ = load_server(tmp_path, monkeypatch)
    server.runtime.settings.approved_host_enabled = True
    monkeypatch.setattr(
        server,
        "assert_approved_host_runtime_immutable",
        lambda: {
            "version": 1,
            "scope": "complete-runtime",
            "path_count": 12,
            "file_count": 5,
            "directory_count": 4,
            "ancestor_directory_count": 3,
            "digest": "a" * 64,
        },
    )

    status = server._approved_host_capability()

    assert status["enabled"] is True
    assert status["available"] is True
    assert status["live_verified"] is True
    assert status["runtime_preflight"]["status"] == "passed"
    assert status["runtime_preflight"]["digest"] == "a" * 64
    assert status["execution_time_recheck"] is True


def test_backup_and_diff_limits_fail_before_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    target = root / "bounded.txt"
    original = "a\n" * 1000
    target.write_text(original, encoding="utf-8")
    server.runtime.settings.max_backup_bytes = 1024
    with pytest.raises(ValueError, match="max_backup_bytes"):
        server.write_file("bounded.txt", "small")
    assert target.read_text(encoding="utf-8") == original

    server.runtime.settings.max_backup_bytes = 4096
    server.runtime.settings.max_diff_bytes = 1024
    with pytest.raises(ValueError, match="max_diff_bytes"):
        server.write_file(
            "bounded.txt",
            "b\n" * 1000,
            expected_sha256=sha256_bytes(target.read_bytes()),
        )
    assert target.read_text(encoding="utf-8") == original


def test_post_commit_failure_refuses_recovery_over_third_party_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    target = root / "race.txt"
    target.write_bytes(b"before")
    replacement = root / "third-party.bin"
    replacement.write_bytes(b"after")

    expected = sha256_bytes(b"before")
    real_capture = server.capture_workspace_state
    real_release = server.release_verified_hold
    swapped = False

    def fail_after_checkpoint(settings, operation_id, stage, *, paths=None):
        if stage == "after":
            raise RuntimeError("forced post-write failure")
        return real_capture(settings, operation_id, stage, paths=paths)

    def release_then_replace(path: Path) -> None:
        nonlocal swapped
        real_release(path)
        if not swapped and Path(str(path)).resolve() == target.resolve():
            os.replace(replacement, target)
            swapped = True

    monkeypatch.setattr(server, "capture_workspace_state", fail_after_checkpoint)
    monkeypatch.setattr(server, "release_verified_hold", release_then_replace)

    with pytest.raises(server.WorkspaceMutationError) as captured:
        server.write_file("race.txt", "after", expected_sha256=expected)

    assert swapped is True
    assert captured.value.recovery_state == "recovery_required"
    assert "automatic recovery refused" in str(captured.value)
    assert target.read_bytes() == b"after"
    assert not replacement.exists()
