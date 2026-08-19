from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.policy import approved_request_hash
from windows_local_mcp.sandbox_backend import (
    SANDBOX_SECURITY_PROPERTIES,
    ApprovedSandboxUnavailable,
    CodexSandboxBackend,
    build_codex_sandbox_argv,
    codex_sandbox_effective_policy,
    codex_sandbox_state,
    guard_and_launch_codex_sandbox,
    isolation_context_digest,
    require_codex_sandbox_live_verification,
    resolve_codex_sandbox_backend,
)
from windows_local_mcp.sandbox_live_verify import (
    _classify_probe_result,
    _host_endpoint_reachable,
    _property_results,
    _protected_information_canary_path,
)
from windows_local_mcp.sandbox_live_verify import _run as run_live_probe
from windows_local_mcp.util import canonical_json, sha256_text
from windows_local_mcp.wfp_guard import GuardVerification, WfpGuardError
from windows_local_mcp.windows_job import WindowsJobLimits, WindowsSandboxJob
from windows_local_mcp.windows_system import windows_system_executable
from windows_local_mcp.workspace_history import (
    capture_workspace_state,
    incomplete_workspace_transactions,
    mark_workspace_transaction_audit_reconciled,
    recover_incomplete_workspace_transaction,
    verify_checkpoint_integrity,
    workspace_recovery_required,
)


def _settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
    )
    settings.ensure_directories()
    return settings


def _guard_verification() -> GuardVerification:
    return GuardVerification(
        guard_version="wlmcp-wfp-loopback-guard-v1",
        policy_generation=1,
        target_account="CodexSandboxOffline",
        target_sid="S-1-5-21-100-200-300-1004",
        app_isolation_sublayer_key="ffe221c3-92a8-4564-a59f-dafb70756020",
        app_isolation_weight=7,
        guard_sublayer_key="7019c9c2-acc9-5a02-97cb-d9ccdca1b9ab",
        guard_sublayer_weight=10,
        v4_filter_key="0acea791-e272-5a9c-ae2f-5bf41970dd41",
        v4_filter_id=501,
        v4_effective_weight=100,
        v6_filter_key="cb98391f-1773-5060-bfb6-3de2306f8baa",
        v6_filter_id=502,
        v6_effective_weight=100,
    )


def _test_backend() -> CodexSandboxBackend:
    return CodexSandboxBackend(
        executable=sys.executable,
        executable_sha256="a" * 64,
        executable_size=1,
        executable_mtime_ns=1,
        windows_mode="elevated",
        permission_profile=":workspace",
        provenance="test",
        signature_status="Valid",
        signer_subject="OpenAI",
        signer_thumbprint="b" * 40,
        helpers=(),
    )


def test_guard_preflight_succeeds_before_codex_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    calls: list[str] = []
    expected = (object(), object(), ["codex", "sandbox"])

    def verify_guard() -> GuardVerification:
        calls.append("guard")
        return _guard_verification()

    def launch(*_args: object, **_kwargs: object) -> tuple[object, object, list[str]]:
        calls.append("launch")
        return expected

    monkeypatch.setattr(
        "windows_local_mcp.wfp_guard_runtime.ensure_runtime_codex_loopback_guard",
        verify_guard,
    )
    monkeypatch.setattr("windows_local_mcp.sandbox_backend.launch_codex_sandbox", launch)
    process, job, argv, guard = guard_and_launch_codex_sandbox(
        _test_backend(),
        settings=settings,
        command=[sys.executable, "-c", "pass"],
        cwd=settings.workspace_root,
        writable_roots=(),
        environment={},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert (process, job, argv) == expected
    assert calls == ["guard", "launch"]
    assert guard["target_sid"] == "S-1-5-21-100-200-300-1004"


@pytest.mark.parametrize(
    "error",
    [
        WfpGuardError("required object is absent"),
        WfpGuardError("read-back verification failed"),
        WfpGuardError("SID/filter/sublayer mismatch"),
        OSError("Guard IPC failed"),
    ],
)
def test_guard_preflight_failure_never_starts_codex_or_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    settings = _settings(tmp_path)
    launch_calls: list[str] = []

    def fail_guard() -> GuardVerification:
        raise error

    def forbidden_launch(*_args: object, **_kwargs: object) -> object:
        launch_calls.append("launch")
        raise AssertionError("Codex launch must not be reached")

    def forbidden_popen(*_args: object, **_kwargs: object) -> object:
        launch_calls.append("popen")
        raise AssertionError("subprocess must not be reached")

    monkeypatch.setattr(
        "windows_local_mcp.wfp_guard_runtime.ensure_runtime_codex_loopback_guard",
        fail_guard,
    )
    monkeypatch.setattr(
        "windows_local_mcp.sandbox_backend.launch_codex_sandbox", forbidden_launch
    )
    monkeypatch.setattr(subprocess, "Popen", forbidden_popen)
    with pytest.raises(ApprovedSandboxUnavailable, match="WFP Guard verification failed"):
        guard_and_launch_codex_sandbox(
            _test_backend(),
            settings=settings,
            command=[sys.executable, "-c", "pass"],
            cwd=settings.workspace_root,
            writable_roots=(),
            environment={},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    assert launch_calls == []


def test_codex_sandbox_adapter_binds_installed_launcher_without_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    codex = tmp_path / "trusted-tools" / "codex.exe"
    codex.parent.mkdir()
    codex.write_bytes(b"test codex launcher")
    (codex.parent / "codex-command-runner.exe").write_bytes(b"test command runner")
    (codex.parent / "codex-windows-sandbox-setup.exe").write_bytes(
        b"test sandbox setup"
    )
    settings.approved_sandbox_codex_path = codex
    monkeypatch.setattr(
        "windows_local_mcp.sandbox_backend._openai_authenticode_identity",
        lambda _path: {
            "status": "Valid",
            "subject": 'CN="OpenAI OpCo, LLC"',
            "thumbprint": "A" * 40,
        },
    )

    backend = resolve_codex_sandbox_backend(settings)
    argv = build_codex_sandbox_argv(
        backend,
        settings=settings,
        command=[sys.executable, "-m", "pytest"],
        cwd=str(settings.workspace_root),
        writable_roots=(settings.workspace_root,),
    )
    assert argv[0] == str(codex.resolve())
    assert argv[1] == "sandbox"
    assert "exec" not in argv[:8]
    state = json.loads(argv[argv.index("--sandbox-state-json") + 1])
    assert state["permissionProfile"]["network"] == "restricted"
    assert "--sandbox-state-disable-network" in argv
    assert backend.as_dict()["model_api_usage"].startswith("none")
    assert backend.as_dict()["authentication_required"] is False
    assert backend.permission_profile == ":workspace"
    assert backend.provenance == "explicit-trusted-local-config"
    assert backend.signature_status == "Valid"
    assert [helper.name for helper in backend.helpers] == [
        "codex-command-runner.exe",
        "codex-windows-sandbox-setup.exe",
    ]


def test_codex_sandbox_rejects_untrusted_launcher_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    codex = tmp_path / "trusted-tools" / "codex.exe"
    codex.parent.mkdir()
    codex.write_bytes(b"unsigned replacement")
    settings.approved_sandbox_codex_path = codex

    def reject(_path: Path) -> dict[str, str]:
        raise ApprovedSandboxUnavailable("not signed by OpenAI")

    monkeypatch.setattr(
        "windows_local_mcp.sandbox_backend._openai_authenticode_identity", reject
    )
    with pytest.raises(ApprovedSandboxUnavailable, match="not found or was not accessible"):
        resolve_codex_sandbox_backend(settings)


def test_codex_policy_is_offline_and_does_not_trust_target_stderr() -> None:
    policy = codex_sandbox_effective_policy(workspace_write=True)
    assert policy["network_policy"]["internet"] == "deny"
    assert policy["filesystem_policy"]["outside_workspace_write"].startswith("denied")


def test_codex_state_limits_reads_and_denies_protected_workspace_paths(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    executable = tmp_path / "tool" / "python.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"tool")
    runtime = settings.sandbox_scratch_dir / "runs" / "state-test"
    runtime.mkdir(parents=True)

    state = codex_sandbox_state(
        settings,
        command=[str(executable), "-c", "pass"],
        cwd=runtime,
        writable_roots=(runtime,),
    )

    profile = state["permissionProfile"]
    assert profile["network"] == "restricted"
    entries = profile["file_system"]["entries"]
    assert {
        "path": {"type": "path", "path": str(settings.workspace_root.resolve())},
        "access": "read",
    } in entries
    assert {
        "path": {"type": "path", "path": str(runtime.resolve())},
        "access": "write",
    } in entries
    patterns = {
        entry["path"]["pattern"] for entry in entries if entry["path"]["type"] == "glob_pattern"
    }
    workspace = settings.workspace_root.resolve().as_posix()
    assert f"{workspace}/**/.env" in patterns
    assert f"{workspace}/**/credentials.json" in patterns
    assert all(str(Path.home()) not in str(entry) for entry in entries)


def test_live_verification_properties_distinguish_failed_from_unverified() -> None:
    properties = _property_results(
        {
            "source_read": True,
            "outside_user_read_denied": False,
            "control_plane_read_denied": True,
            "scratch_write": True,
            "source_workspace_write_denied": True,
            "outside_user_write_denied": True,
            "control_plane_write_denied": True,
        }
    )

    assert properties["filesystem_read"]["status"] == "failed"
    assert properties["filesystem_read"]["failed"] == ["outside_user_read_denied"]
    assert properties["filesystem_write"]["status"] == "verified"
    assert properties["resource_bound"]["status"] == "unverified"
    assert properties["resource_bound"]["failed"] == []
    assert "process_limit_enforced" in properties["resource_bound"]["unverified"]
    assert properties["internet"]["status"] == "unverified"
    assert properties["internet"]["unverified"] == ["internet_denied"]
    assert properties["lan"]["status"] == "unverified"
    assert properties["lan"]["unverified"] == ["lan_denied"]

    failed_network = _property_results(
        {"internet_denied": False, "lan_denied": False}
    )
    assert failed_network["internet"]["status"] == "failed"
    assert failed_network["lan"]["status"] == "failed"


def test_live_probe_classification_does_not_overclaim_diagnostic_failures() -> None:
    launch_failure = subprocess.CompletedProcess([], -255, b"", b"")
    timeout = subprocess.CompletedProcess([], -254, b"", b"")
    boundary_escape = subprocess.CompletedProcess([], 9, b"", b"")
    denial = subprocess.CompletedProcess([], 0, b"denied", b"")

    assert _classify_probe_result(launch_failure, success=False)[0] is None
    assert _classify_probe_result(timeout, success=False)[0] is None
    assert _classify_probe_result(boundary_escape, success=False)[0] is False
    assert _classify_probe_result(denial, success=True)[0] is True
    assert _classify_probe_result(
        subprocess.CompletedProcess([], 1, b"probe setup error", b""), success=False
    )[0] is None


def test_protected_information_canary_uses_exact_blocked_filename(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    first = _protected_information_canary_path(workspace)
    second = _protected_information_canary_path(workspace)

    assert first.name == ".env"
    assert first.parent.parent == workspace
    assert first.parent.name.startswith(".wlmcp-live-protected-")
    assert second.parent != first.parent


def test_host_endpoint_control_distinguishes_reachable_from_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[str, int], float]] = []

    class Connection:
        def close(self) -> None:
            return None

    def connect(endpoint: tuple[str, int], *, timeout: float) -> Connection:
        calls.append((endpoint, timeout))
        return Connection()

    monkeypatch.setattr("socket.create_connection", connect)
    assert _host_endpoint_reachable("1.1.1.1", 443, timeout=3) is True
    assert calls == [(("1.1.1.1", 443), 3)]

    def unavailable(_endpoint: tuple[str, int], *, timeout: float) -> Connection:
        raise OSError(f"unreachable after {timeout}")

    monkeypatch.setattr("socket.create_connection", unavailable)
    assert _host_endpoint_reachable("1.1.1.1", 443) is False


def test_sandbox_live_verification_is_property_scoped_and_fails_closed(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    backend = CodexSandboxBackend(
        executable=str(tmp_path / "codex.exe"),
        executable_sha256="a" * 64,
        executable_size=1,
        executable_mtime_ns=1,
        windows_mode="elevated",
        permission_profile=":workspace",
        provenance="test",
        signature_status="Valid",
        signer_subject="OpenAI",
        signer_thumbprint="b" * 40,
        helpers=(),
    )
    marker = settings.data_dir / "control-plane" / "sandbox-live-verification.json"
    backend_digest = sha256_text(canonical_json(backend.as_dict()))
    marker.write_text(
        canonical_json(
            {
                "version": 1,
                "passed": True,
                "backend_digest": backend_digest,
                "checks": {"network_denied": True},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ApprovedSandboxUnavailable, match="missing, failed, or stale"):
        require_codex_sandbox_live_verification(settings, backend)

    properties = {
        name: {"status": "verified"} for name in SANDBOX_SECURITY_PROPERTIES
    }
    properties["resource_bound"] = {"status": "unverified"}
    marker.write_text(
        canonical_json(
            {
                "version": 2,
                "passed": True,
                "backend_digest": backend_digest,
                "properties": properties,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ApprovedSandboxUnavailable, match="missing, failed, or stale"):
        require_codex_sandbox_live_verification(settings, backend)

    properties["resource_bound"] = {"status": "verified"}
    marker.write_text(
        canonical_json(
            {
                "version": 3,
                "passed": True,
                "backend_digest": backend_digest,
                "isolation_context_digest": isolation_context_digest(settings, backend),
                "properties": properties,
            }
        ),
        encoding="utf-8",
    )
    assert require_codex_sandbox_live_verification(settings, backend)["version"] == 3

    settings.approved_sandbox_require_live_verification = False
    with pytest.raises(ApprovedSandboxUnavailable, match="cannot be disabled"):
        require_codex_sandbox_live_verification(settings, backend)


def test_live_marker_is_stale_after_security_context_changes(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    backend = CodexSandboxBackend(
        executable=str(tmp_path / "codex.exe"),
        executable_sha256="a" * 64,
        executable_size=1,
        executable_mtime_ns=1,
        windows_mode="elevated",
        permission_profile=":workspace",
        provenance="test",
        signature_status="Valid",
        signer_subject="OpenAI",
        signer_thumbprint="b" * 40,
        helpers=(),
    )
    marker = settings.data_dir / "control-plane" / "sandbox-live-verification.json"
    original_digest = isolation_context_digest(settings, backend)
    marker.write_text(
        canonical_json(
            {
                "version": 3,
                "passed": True,
                "backend_digest": sha256_text(canonical_json(backend.as_dict())),
                "isolation_context_digest": original_digest,
                "properties": {
                    name: {"status": "verified"}
                    for name in SANDBOX_SECURITY_PROPERTIES
                },
            }
        ),
        encoding="utf-8",
    )
    assert require_codex_sandbox_live_verification(settings, backend)["version"] == 3

    original_blocked = list(settings.blocked_file_names)
    original_dependencies = list(settings.sandbox_dependency_readable_paths)
    original_processes = settings.max_sandbox_processes
    original_memory = settings.max_sandbox_memory_bytes
    changes = (
        lambda: settings.blocked_file_names.append("changed-security-name"),
        lambda: settings.sandbox_dependency_readable_paths.append(
            tmp_path / "readable-dependency"
        ),
        lambda: setattr(settings, "max_sandbox_processes", original_processes + 1),
        lambda: setattr(settings, "max_sandbox_memory_bytes", original_memory + 1),
    )
    for change in changes:
        settings.blocked_file_names = list(original_blocked)
        settings.sandbox_dependency_readable_paths = list(original_dependencies)
        settings.max_sandbox_processes = original_processes
        settings.max_sandbox_memory_bytes = original_memory
        change()
        with pytest.raises(ApprovedSandboxUnavailable, match="missing, failed, or stale"):
            require_codex_sandbox_live_verification(settings, backend)

    settings.blocked_file_names = list(reversed(original_blocked))
    settings.sandbox_dependency_readable_paths = list(original_dependencies)
    settings.max_sandbox_processes = original_processes
    settings.max_sandbox_memory_bytes = original_memory
    assert isolation_context_digest(settings, backend) == original_digest


def test_live_probe_launch_failure_is_unverified_and_does_not_raise(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    backend = CodexSandboxBackend(
        executable=sys.executable,
        executable_sha256="a" * 64,
        executable_size=1,
        executable_mtime_ns=1,
        windows_mode="elevated",
        permission_profile=":workspace",
        provenance="test",
        signature_status="Valid",
        signer_subject="OpenAI",
        signer_thumbprint="b" * 40,
        helpers=(),
    )

    def unavailable(*_args: object, **_kwargs: object) -> object:
        raise OSError("sandbox launcher unavailable")

    monkeypatch.setattr(
        "windows_local_mcp.sandbox_live_verify.guard_and_launch_codex_sandbox",
        unavailable,
    )
    probe_diagnostics: list[dict[str, object]] = []
    result = run_live_probe(
        settings,
        backend,
        settings.sandbox_scratch_dir,
        [sys.executable, "-c", "pass"],
        probe_name="launch-failure-regression",
        probe_diagnostics=probe_diagnostics,
    )

    assert result.returncode == -255
    value, reason = _classify_probe_result(result, success=False)
    assert value is None
    assert reason.startswith("unverified:")
    assert probe_diagnostics[0]["pid"] is None
    assert probe_diagnostics[0]["classification"] == "unverified"


def test_independent_probe_launch_failure_does_not_stop_next_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    backend = CodexSandboxBackend(
        executable=sys.executable,
        executable_sha256="a" * 64,
        executable_size=1,
        executable_mtime_ns=1,
        windows_mode="elevated",
        permission_profile=":workspace",
        provenance="test",
        signature_status="Valid",
        signer_subject="OpenAI",
        signer_thumbprint="b" * 40,
        helpers=(),
    )
    monkeypatch.setattr(
        "windows_local_mcp.sandbox_live_verify.guard_and_launch_codex_sandbox",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("launch failed")),
    )
    diagnostics: list[dict[str, object]] = []
    results = [
        run_live_probe(
            settings,
            backend,
            settings.sandbox_scratch_dir,
            [sys.executable, "-c", "pass"],
            probe_name=name,
            probe_diagnostics=diagnostics,
        )
        for name in ("first-independent-probe", "second-independent-probe")
    ]

    assert [result.returncode for result in results] == [-255, -255]
    assert [item["probe"] for item in diagnostics] == [
        "first-independent-probe",
        "second-independent-probe",
    ]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object resource check")
def test_windows_job_object_process_limit_regression(tmp_path: Path) -> None:
    python = str((Path(sys.base_prefix) / "python.exe").resolve(strict=True))
    child_code = "import time;time.sleep(60)"
    parent_code = (
        "import subprocess,sys,time;"
        f"[subprocess.Popen([sys.executable,'-I','-c',{child_code!r}]) for _ in range(16)];"
        "time.sleep(60)"
    )
    job = WindowsSandboxJob(
        WindowsJobLimits(max_processes=4, max_memory_bytes=512 * 1024 * 1024)
    )
    process = job.popen(
        [python, "-I", "-c", parent_code],
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
    )
    try:
        assert job.violation_event.wait(20)
        assert job.violation == "process_count_limit"
        job.terminate()
        process.wait(timeout=10)
        assert job.wait_empty(timeout=10)
    finally:
        job.close()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object resource check")
def test_windows_job_object_memory_limit_regression(tmp_path: Path) -> None:
    python = str((Path(sys.base_prefix) / "python.exe").resolve(strict=True))
    allocation = 80 * 1024 * 1024
    child_code = (
        "import time;"
        f"x=bytearray({allocation});x[::4096]=b'\\x01'*({allocation}//4096);"
        "time.sleep(60)"
    )
    parent_code = (
        "import subprocess,sys,time;"
        f"x=bytearray({allocation});x[::4096]=b'\\x01'*({allocation}//4096);"
        f"subprocess.Popen([sys.executable,'-I','-c',{child_code!r}]);"
        "time.sleep(60)"
    )
    job = WindowsSandboxJob(
        WindowsJobLimits(max_processes=8, max_memory_bytes=128 * 1024 * 1024)
    )
    process = job.popen(
        [python, "-I", "-c", parent_code],
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
    )
    try:
        assert job.violation_event.wait(20)
        assert job.violation == "process_tree_memory_limit"
        job.terminate()
        process.wait(timeout=10)
        assert job.wait_empty(timeout=10)
    finally:
        job.close()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows process-tree live check")
def test_live_probe_timeout_terminates_descendant_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    python = str((Path(sys.base_prefix) / "python.exe").resolve(strict=True))
    backend = CodexSandboxBackend(
        executable=python,
        executable_sha256="a" * 64,
        executable_size=Path(python).stat().st_size,
        executable_mtime_ns=Path(python).stat().st_mtime_ns,
        windows_mode="elevated",
        permission_profile=":workspace",
        provenance="test",
        signature_status="Valid",
        signer_subject="OpenAI",
        signer_thumbprint="b" * 40,
        helpers=(),
    )
    heartbeat = settings.sandbox_scratch_dir / "timeout-heartbeat.bin"
    child_code = (
        "from pathlib import Path\n"
        "import time\n"
        f"path=Path({str(heartbeat)!r})\n"
        "while True:\n"
        " with path.open('ab') as output: output.write(b'x')\n"
        " time.sleep(.05)\n"
    )
    parent_code = (
        "import subprocess,sys,time;"
        f"subprocess.Popen([sys.executable,'-I','-c',{child_code!r}]);"
        "time.sleep(60)"
    )

    def launch_direct(
        _backend: CodexSandboxBackend,
        *,
        command: list[str],
        cwd: Path,
        environment: dict[str, str],
        stdin: object,
        stdout: object,
        stderr: object,
        **_kwargs: object,
    ) -> tuple[subprocess.Popen[bytes], WindowsSandboxJob, list[str], dict[str, object]]:
        job = WindowsSandboxJob(
            WindowsJobLimits(max_processes=8, max_memory_bytes=512 * 1024 * 1024)
        )
        process = job.popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            shell=False,
        )
        return process, job, command, _guard_verification().as_dict()

    monkeypatch.setattr(
        "windows_local_mcp.sandbox_live_verify.guard_and_launch_codex_sandbox",
        launch_direct,
    )

    probe_diagnostics: list[dict[str, object]] = []
    with pytest.raises(subprocess.TimeoutExpired):
        run_live_probe(
            settings,
            backend,
            settings.sandbox_scratch_dir,
            [python, "-I", "-c", parent_code],
            timeout=1,
            probe_name="timeout-regression",
            probe_diagnostics=probe_diagnostics,
            raise_on_timeout=True,
        )

    size_after_stop = heartbeat.stat().st_size
    time.sleep(0.3)
    assert heartbeat.stat().st_size == size_after_stop
    assert probe_diagnostics[0]["probe"] == "timeout-regression"
    assert probe_diagnostics[0]["pid"]
    assert probe_diagnostics[0]["timed_out"] is True
    assert probe_diagnostics[0]["child_process_state"] == "terminated_and_drained"


def test_approved_request_hash_binds_capability_fields() -> None:
    request: dict[str, object] = {
        "approval_binding_version": 3,
        "normalized_command": {"executable": "python.exe", "args": ["test.py"]},
        "workspace_write": False,
        "max_runtime_seconds": 30,
        "sandbox_backend": {"executable_sha256": "a" * 64},
    }
    expected = approved_request_hash(request)
    for key, value in (
        ("workspace_write", True),
        ("max_runtime_seconds", 300),
        ("sandbox_backend", {"executable_sha256": "b" * 64}),
    ):
        changed = dict(request)
        changed[key] = value
        assert approved_request_hash(changed) != expected


def test_safe_readable_path_cannot_overlap_security_roots(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with pytest.raises(ValidationError, match="cannot overlap"):
        Settings(
            workspace_root=workspace,
            data_dir=tmp_path / "data",
            protect_data_dir_acl=False,
            sandbox_dependency_readable_paths=[tmp_path],
        )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows system-directory contract")
def test_windows_policy_helpers_ignore_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(Path.cwd()))
    resolved = Path(windows_system_executable("icacls.exe"))
    assert resolved.is_file()
    assert resolved.name.casefold() == "icacls.exe"
    assert resolved.parent != Path.cwd()


def test_checkpoint_read_failure_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    target = settings.workspace_root / "locked.txt"
    target.write_text("important", encoding="utf-8")
    original = Path.read_bytes

    def fail_target(path: Path) -> bytes:
        if path == target:
            raise PermissionError("sharing violation")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", fail_target)
    with pytest.raises(RuntimeError, match="could not capture locked.txt"):
        capture_workspace_state(settings, "capture-failure", "before")


def test_checkpoint_without_complete_capture_marker_is_rejected(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    operation = settings.data_dir / "workspace-history" / "operations" / "legacy" / "before"
    operation.mkdir(parents=True)
    manifest = operation / "manifest.json"
    manifest.write_text(
        json.dumps({"version": 2, "operation_id": "legacy", "stage": "before", "files": []}),
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="complete-capture marker"):
        verify_checkpoint_integrity(settings, str(manifest))


def test_preflight_and_staged_journals_become_terminal_without_recovery(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    (settings.workspace_root / "a.txt").write_text("safe", encoding="utf-8")
    before = capture_workspace_state(settings, "staged-journal", "before")
    transaction = settings.data_dir / "workspace-history" / "transactions" / "staged-journal"
    transaction.mkdir()
    journal_path = transaction / "journal.json"
    journal_path.write_text(
        json.dumps(
            {
                "version": 1,
                "operation_id": "staged-journal",
                "kind": "workspace_restore",
                "state": "staged",
                "before_manifest": before.manifest_path,
                "target_manifest": before.manifest_path,
                "applied_paths": [],
            }
        ),
        encoding="utf-8",
    )
    journal = incomplete_workspace_transactions(settings)[0]
    recovered = recover_incomplete_workspace_transaction(settings, journal)
    assert recovered["state"] == "failed_preflight"
    mark_workspace_transaction_audit_reconciled(settings, "staged-journal")
    assert incomplete_workspace_transactions(settings) == []
    assert workspace_recovery_required(settings) is False


def test_corrupt_journal_blocks_mutation_fail_closed(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    transaction = settings.data_dir / "workspace-history" / "transactions" / "corrupt-op"
    transaction.mkdir()
    (transaction / "journal.json").write_bytes(b"not-json")
    journals = incomplete_workspace_transactions(settings)
    assert journals[0]["state"] == "recovery_required"
    assert workspace_recovery_required(settings) is True


def test_applied_verified_journal_restores_audit_consistency(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    (settings.workspace_root / "a.txt").write_text("target", encoding="utf-8")
    target = capture_workspace_state(settings, "applied-op", "after")
    audit = AuditStore(settings)
    audit.create_operation(
        operation_id="applied-op",
        tool_name="request_workspace_rollback",
        tier="approved_host",
        status="running",
        cwd=str(settings.workspace_root),
        request={},
    )
    transaction = settings.data_dir / "workspace-history" / "transactions" / "applied-op"
    transaction.mkdir()
    journal_path = transaction / "journal.json"
    journal_path.write_text(
        json.dumps(
            {
                "version": 1,
                "operation_id": "applied-op",
                "kind": "workspace_restore",
                "state": "applied_verified",
                "before_manifest": target.manifest_path,
                "target_manifest": target.manifest_path,
                "changed_paths": [],
                "applied_paths": [],
            }
        ),
        encoding="utf-8",
    )
    reconciled = AuditStore(settings).get_operation("applied-op", include_events=False)
    assert reconciled["status"] == "succeeded"
    assert reconciled["post_workspace_path"] == target.manifest_path
    assert json.loads(journal_path.read_text(encoding="utf-8"))["state"] == "complete"


def test_applied_verified_terminal_error_records_owned_after_checkpoint(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    (settings.workspace_root / "a.txt").write_text("applied", encoding="utf-8")
    foreign_target = capture_workspace_state(settings, "old-target", "after")
    audit = AuditStore(settings)
    audit.create_operation(
        operation_id="failed-rollback",
        tool_name="request_workspace_rollback",
        tier="approved_host",
        status="failed",
        cwd=str(settings.workspace_root),
        request={},
    )
    transaction = (
        settings.data_dir
        / "workspace-history"
        / "transactions"
        / "failed-rollback"
    )
    transaction.mkdir()
    journal_path = transaction / "journal.json"
    journal_path.write_text(
        json.dumps(
            {
                "version": 1,
                "operation_id": "failed-rollback",
                "kind": "workspace_restore",
                "state": "applied_verified",
                "before_manifest": foreign_target.manifest_path,
                "target_manifest": foreign_target.manifest_path,
                "changed_paths": [],
                "applied_paths": [],
            }
        ),
        encoding="utf-8",
    )

    reconciled = AuditStore(settings).get_operation(
        "failed-rollback", include_events=False
    )
    owned_after = (
        settings.data_dir
        / "workspace-history"
        / "operations"
        / "failed-rollback"
        / "after"
        / "manifest.json"
    )
    assert reconciled["status"] == "succeeded"
    assert reconciled["post_workspace_path"] == str(owned_after.resolve(strict=True))
    verify_checkpoint_integrity(settings, str(owned_after))
    assert json.loads(owned_after.read_text(encoding="utf-8"))["capture_complete"] is True
    assert json.loads(journal_path.read_text(encoding="utf-8"))["state"] == "complete"


def test_legacy_complete_journal_repairs_audit_before_marking_reconciled(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    (settings.workspace_root / "a.txt").write_text("applied", encoding="utf-8")
    foreign_target = capture_workspace_state(settings, "legacy-target", "after")
    audit = AuditStore(settings)
    audit.create_operation(
        operation_id="legacy-complete",
        tool_name="request_workspace_rollback",
        tier="approved_host",
        status="running",
        cwd=str(settings.workspace_root),
        request={},
    )
    transaction = (
        settings.data_dir
        / "workspace-history"
        / "transactions"
        / "legacy-complete"
    )
    transaction.mkdir()
    journal_path = transaction / "journal.json"
    journal_path.write_text(
        json.dumps(
            {
                "version": 1,
                "operation_id": "legacy-complete",
                "kind": "workspace_restore",
                "state": "complete",
                "before_manifest": foreign_target.manifest_path,
                "target_manifest": foreign_target.manifest_path,
                "changed_paths": [],
                "applied_paths": [],
            }
        ),
        encoding="utf-8",
    )

    reconciled = AuditStore(settings).get_operation(
        "legacy-complete", include_events=False
    )
    owned_after = (
        settings.data_dir
        / "workspace-history"
        / "operations"
        / "legacy-complete"
        / "after"
        / "manifest.json"
    )
    assert reconciled["status"] == "succeeded"
    assert reconciled["post_workspace_path"] == str(owned_after.resolve(strict=True))
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    assert journal["state"] == "complete"
    assert journal["audit_reconciled"] is True
    assert incomplete_workspace_transactions(settings) == []
