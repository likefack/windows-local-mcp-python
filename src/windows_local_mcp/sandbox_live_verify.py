from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from contextlib import ExitStack
from functools import wraps
from pathlib import Path
from typing import Any

from .child_env import build_command_environment, sanitize_executable_search_path
from .config import Settings
from .process_utils import (
    capture_process_identity,
    process_tree_write_bytes,
)
from .redaction import redact_text
from .resources import NamedControlPlaneLock, scan_directory_bounded
from .sandbox_backend import (
    SANDBOX_LIVE_MARKER_VERSION,
    SANDBOX_SECURITY_PROPERTIES,
    CodexSandboxBackend,
    guard_and_launch_codex_sandbox,
    hold_codex_sandbox_backend,
    probe_codex_version,
    resolve_codex_sandbox_backend,
    sandbox_isolation_context,
)
from .util import canonical_json, sha256_text, utc_now_iso
from .wfp_guard import GuardVerification, guard_verification_binding
from .wfp_guard_identity import hold_wfp_guard_implementation
from .wfp_guard_runtime import ensure_runtime_codex_loopback_guard
from .windows_job import WindowsJobLimits, WindowsSandboxJob
from .windows_system import windows_system_executable

_LAUNCH_FAILURE_RETURN_CODE = -255
_TIMEOUT_RETURN_CODE = -254
_PROBE_ERROR_RETURN_CODE = -253
_BOUNDARY_ESCAPE_EXIT_CODE = 9
ProbeCheck = bool | None


def _sandbox_verification_serialized(function: Any) -> Any:
    @wraps(function)
    def locked(settings: Settings, *args: Any, **kwargs: Any) -> Any:
        with NamedControlPlaneLock(settings, "sandbox-verification", timeout=180):
            return function(settings, *args, **kwargs)

    return locked


def _write_evidence(marker: Path, result: dict[str, Any]) -> None:
    temporary_marker = marker.with_name(f".{marker.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary_marker.open("x", encoding="utf-8", newline="\n") as output:
            output.write(canonical_json(result))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_marker, marker)
    finally:
        temporary_marker.unlink(missing_ok=True)


def _c7_marker_identity(
    settings: Settings,
    backend: CodexSandboxBackend,
    *,
    backend_version: str | None,
    guard_implementation: dict[str, Any] | None,
    guard_verification: GuardVerification | None,
) -> dict[str, Any]:
    """Build the mandatory v4 identity fields without inventing failed evidence."""

    context = sandbox_isolation_context(settings, backend)
    os_identity = context["windows_os_identity"]
    binding = (
        guard_verification_binding(guard_verification)
        if guard_verification is not None
        else None
    )
    return {
        "version": SANDBOX_LIVE_MARKER_VERSION,
        "backend_digest": sha256_text(canonical_json(backend.as_dict())),
        "backend_version": backend_version,
        "isolation_context_digest": sha256_text(canonical_json(context)),
        "guard_implementation": guard_implementation,
        "guard_implementation_digest": (
            guard_implementation.get("digest")
            if isinstance(guard_implementation, dict)
            else None
        ),
        "windows_os_identity": os_identity,
        "windows_os_identity_digest": sha256_text(canonical_json(os_identity)),
        "sandbox_account_identity": (
            binding.get("sandbox_account_identity")
            if isinstance(binding, dict)
            else None
        ),
        "wfp_guard_binding": binding,
        "wfp_guard_binding_digest": (
            sha256_text(canonical_json(binding)) if isinstance(binding, dict) else None
        ),
    }


def _protected_information_canary_path(workspace_root: Path) -> Path:
    return workspace_root / f".wlmcp-live-protected-{uuid.uuid4().hex}" / ".env"


def _host_endpoint_reachable(host: str, port: int, *, timeout: float = 2) -> bool:
    try:
        connection = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return False
    connection.close()
    return True


def _property_results(
    checks: dict[str, ProbeCheck], reasons: dict[str, str] | None = None
) -> dict[str, dict[str, Any]]:
    """Translate concrete probes into contract-level properties without overclaiming."""
    requirements = {
        "filesystem_read": (
            "source_workspace_read_denied",
            "outside_user_read_denied",
            "control_plane_read_denied",
        ),
        "filesystem_write": (
            "scratch_write",
            "source_workspace_write_denied",
            "outside_user_write_denied",
            "control_plane_write_denied",
        ),
        "protected_information_read": ("protected_information_denied",),
        "internet": ("internet_denied",),
        "lan": ("lan_denied",),
        "loopback": ("loopback_denied",),
        "descendant_containment": (
            "child_source_workspace_read_denied",
            "child_source_workspace_write_denied",
            "child_outside_user_read_denied",
            "child_protected_information_denied",
            "child_control_plane_read_denied",
            "child_control_plane_write_denied",
            "child_internet_denied",
            "child_lan_denied",
            "child_loopback_denied",
            "grandchild_source_workspace_read_denied",
            "grandchild_source_workspace_write_denied",
            "grandchild_outside_user_read_denied",
            "grandchild_protected_information_denied",
            "grandchild_control_plane_read_denied",
            "grandchild_control_plane_write_denied",
            "grandchild_internet_denied",
            "grandchild_lan_denied",
            "grandchild_loopback_denied",
        ),
        "termination": ("timeout_terminated",),
        "resource_bound": (
            "filesystem_limit_enforced",
            "filesystem_entry_limit_enforced",
            "process_limit_enforced",
            "memory_limit_enforced",
        ),
    }
    result: dict[str, dict[str, Any]] = {}
    for property_name in SANDBOX_SECURITY_PROPERTIES:
        required = requirements[property_name]
        failed = [name for name in required if checks.get(name) is False]
        unverified = [
            name for name in required if name not in checks or checks.get(name) is None
        ]
        incomplete = [name for name in required if checks.get(name) is not True]
        status_reasons = {
            name: reasons[name]
            for name in (*failed, *unverified)
            if reasons is not None and name in reasons
        }
        result[property_name] = {
            "status": (
                "verified"
                if not incomplete
                else "failed"
                if failed
                else "unverified"
            ),
            "checks": list(required),
            "failed": failed,
            "unverified": unverified,
            "missing_or_failed": incomplete,
            "reasons": status_reasons,
        }
    return result


def _return_code_reason(returncode: int | None) -> str:
    if returncode == _LAUNCH_FAILURE_RETURN_CODE:
        return "unverified: Sandbox process launch failed"
    if returncode == _TIMEOUT_RETURN_CODE:
        return "unverified: probe timed out"
    if returncode == _PROBE_ERROR_RETURN_CODE:
        return "unverified: probe execution or cleanup failed"
    if returncode is None:
        return "unverified: probe did not produce an exit code"
    return f"unverified: probe exited with diagnostic code {returncode}"


def _classify_probe_result(
    result: subprocess.CompletedProcess[bytes],
    *,
    success: bool,
    boundary_escape_code: int | None = _BOUNDARY_ESCAPE_EXIT_CODE,
) -> tuple[ProbeCheck, str]:
    """Classify an executed probe without treating diagnostic failure as boundary escape."""

    if result.returncode in {
        _LAUNCH_FAILURE_RETURN_CODE,
        _TIMEOUT_RETURN_CODE,
        _PROBE_ERROR_RETURN_CODE,
    }:
        return None, _return_code_reason(result.returncode)
    if boundary_escape_code is not None and result.returncode == boundary_escape_code:
        return False, "failed: probe observed a boundary escape"
    if result.returncode != 0:
        return None, _return_code_reason(result.returncode)
    if not success:
        return None, "unverified: probe output or postcondition was not measurable"
    return True, "verified: probe completed and the requested boundary held"


def _record_probe_setup_failure(
    probe_diagnostics: list[dict[str, Any]],
    *,
    probe: str,
    started: float,
    error: BaseException,
    error_key: str = "probe_error",
    argv: list[str] | None = None,
    pid: int | None = None,
    child_process_state: str = "probe_setup_failed",
) -> None:
    message = redact_text(f"{type(error).__name__}: {error}")[:1000]
    timed_out = isinstance(error, subprocess.TimeoutExpired)
    probe_diagnostics.append(
        {
            "probe": probe,
            "pid": pid,
            "argv": [redact_text(value)[:1000] for value in (argv or [])],
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "timeout_seconds": getattr(error, "timeout", None),
            "timed_out": timed_out,
            "exit_code": None,
            error_key: message,
            "probe_error": message,
            "stdout": "",
            "stderr": "",
            "child_process_state": child_process_state,
            "final_child_state": child_process_state,
            "classification": "unverified",
            "classification_reason": "unverified: probe setup failed",
        }
    )


def _set_check(
    checks: dict[str, ProbeCheck],
    reasons: dict[str, str],
    name: str,
    value: ProbeCheck,
    reason: str,
) -> None:
    checks[name] = value
    reasons[name] = reason


def _python_executable(settings: Settings) -> str:
    candidate = (Path(sys.base_prefix) / "python.exe").resolve(strict=True)
    for protected in (settings.workspace_root, settings.data_dir):
        try:
            candidate.relative_to(protected)
        except ValueError:
            continue
        raise RuntimeError("live verification Python is inside an untrusted root")
    return str(candidate)


def _environment(settings: Settings, backend: CodexSandboxBackend, nonce: str) -> dict[str, str]:
    environment = build_command_environment(
        os.environ,
        extra_names=settings.child_environment_allowlist,
        nonce=nonce,
    )
    assert settings.sandbox_scratch_dir is not None
    sanitize_executable_search_path(
        environment,
        forbidden_roots=(
            settings.workspace_root,
            settings.data_dir,
            settings.sandbox_scratch_dir,
        ),
        prepend=(Path(backend.executable).parent,),
    )
    return environment


def _run(
    settings: Settings,
    backend: CodexSandboxBackend,
    cwd: Path,
    command: list[str],
    *,
    timeout: float = 20,
    probe_name: str | None = None,
    probe_diagnostics: list[dict[str, Any]] | None = None,
    raise_on_timeout: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    nonce = uuid.uuid4().hex
    started = time.monotonic()
    try:
        process, job, argv, _guard = guard_and_launch_codex_sandbox(
            backend,
            settings=settings,
            command=command,
            cwd=cwd,
            writable_roots=(cwd,),
            environment=_environment(settings, backend, nonce),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except Exception as error:  # noqa: BLE001 - one probe must not cancel independent probes
        message = redact_text(f"{type(error).__name__}: {error}")[:1000]
        diagnostic = {
            "probe": probe_name or "unnamed",
            "argv": [redact_text(value)[:1000] for value in command],
            "pid": None,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "timeout_seconds": timeout,
            "timed_out": False,
            "exit_code": None,
            "launch_error": message,
            "probe_error": message,
            "stdout": "",
            "stderr": "",
            "child_process_state": "launch_failed_before_process_creation",
            "final_child_state": "launch_failed_before_process_creation",
            "classification": "unverified",
            "classification_reason": "unverified: Sandbox process launch failed",
        }
        if probe_diagnostics is not None:
            probe_diagnostics.append(diagnostic)
        return subprocess.CompletedProcess(command, _LAUNCH_FAILURE_RETURN_CODE, b"", b"")
    diagnostic = {
        "probe": probe_name or "unnamed",
        "argv": [redact_text(value)[:1000] for value in argv],
        "pid": process.pid,
        "timeout_seconds": timeout,
    }
    timed_out = False
    stdout = b""
    stderr = b""
    result_returncode = _PROBE_ERROR_RETURN_CODE
    error_message: str | None = None
    try:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            result_returncode = process.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            diagnostic.update(
                {
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "timed_out": True,
                    "child_process_state": "termination_requested",
                }
            )
            job.terminate()
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired as cleanup_error:
                process.kill()
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
                error_message = (
                    "timed-out Sandbox verification process tree could not be drained: "
                    f"{type(cleanup_error).__name__}"
                )
                result_returncode = _PROBE_ERROR_RETURN_CODE
            result_returncode = _TIMEOUT_RETURN_CODE
        except Exception as error:  # noqa: BLE001 - diagnostics must remain independent
            error_message = redact_text(f"{type(error).__name__}: {error}")[:1000]
            result_returncode = _PROBE_ERROR_RETURN_CODE
    finally:
        job.terminate()
        if not job.wait_empty(timeout=10):
            diagnostic["job_cleanup"] = "descendants_remained"
            diagnostic["child_process_state"] = "descendants_remaining"
            result_returncode = _PROBE_ERROR_RETURN_CODE
        job.close()
    if error_message:
        diagnostic["probe_error"] = error_message
    if timed_out:
        diagnostic["child_process_state"] = "terminated_and_drained"
    diagnostic.update(
        {
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "timed_out": timed_out,
            "exit_code": result_returncode,
            "stdout": redact_text(stdout.decode("utf-8", errors="replace"))[:2000],
            "stderr": redact_text(stderr.decode("utf-8", errors="replace"))[:2000],
            "child_process_state": diagnostic.get(
                "child_process_state", "exited_and_drained"
            ),
            "final_child_state": diagnostic.get(
                "child_process_state", "exited_and_drained"
            ),
            "classification": (
                "unverified"
                if result_returncode in {
                    _LAUNCH_FAILURE_RETURN_CODE,
                    _TIMEOUT_RETURN_CODE,
                    _PROBE_ERROR_RETURN_CODE,
                }
                else "executed"
            ),
            "classification_reason": _return_code_reason(result_returncode)
            if result_returncode in {
                _LAUNCH_FAILURE_RETURN_CODE,
                _TIMEOUT_RETURN_CODE,
                _PROBE_ERROR_RETURN_CODE,
            }
            else "probe executed; boundary result is classified by its caller",
        }
    )
    if probe_diagnostics is not None:
        probe_diagnostics.append(diagnostic)
    if timed_out and raise_on_timeout:
        raise subprocess.TimeoutExpired(argv, timeout)
    return subprocess.CompletedProcess(argv, result_returncode, stdout, stderr)


def _launch_resource_probe(
    settings: Settings,
    backend: CodexSandboxBackend,
    *,
    command: list[str],
    cwd: Path,
    environment: dict[str, str],
    limits: WindowsJobLimits | None,
    probe_name: str,
    probe_diagnostics: list[dict[str, Any]],
    started: float,
) -> tuple[subprocess.Popen[Any], WindowsSandboxJob, list[str]] | None:
    try:
        process, job, argv, _guard = guard_and_launch_codex_sandbox(
            backend,
            settings=settings,
            command=command,
            cwd=cwd,
            writable_roots=(cwd,),
            environment=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            limits=limits,
        )
        return process, job, argv
    except Exception as error:  # noqa: BLE001 - one independent probe must not stop others
        _record_probe_setup_failure(
            probe_diagnostics,
            probe=probe_name,
            started=started,
            error=error,
            error_key="launch_error",
            argv=command,
        )
        return None


def _termination_probe(
    settings: Settings,
    backend: CodexSandboxBackend,
    root: Path,
    python: str,
    probe_diagnostics: list[dict[str, Any]],
) -> tuple[ProbeCheck, str]:
    started = time.monotonic()
    heartbeat = root / "heartbeat.bin"
    heartbeat_code = (
        "from pathlib import Path\n"
        "import time\n"
        "path=Path('heartbeat.bin')\n"
        "while True:\n"
        " with path.open('ab') as output: output.write(b'x')\n"
        " time.sleep(.1)\n"
    )
    command = [
        python,
        "-I",
        "-c",
        (
            "import subprocess,sys,time;"
            f"subprocess.Popen([sys.executable,'-I','-c',{heartbeat_code!r}]);"
            "time.sleep(60)"
        ),
    ]
    nonce = uuid.uuid4().hex
    launched = _launch_resource_probe(
        settings,
        backend,
        command=command,
        cwd=root,
        environment=_environment(settings, backend, nonce),
        limits=None,
        probe_name="timeout_terminated",
        probe_diagnostics=probe_diagnostics,
        started=started,
    )
    if launched is None:
        return None, "unverified: termination probe launch failed"
    running, job, argv = launched
    terminated = False
    empty = False
    size_before = 0
    size_after = 0
    try:
        time.sleep(2)
        terminated = job.terminate()
        running.wait(timeout=10)
        empty = job.wait_empty(timeout=10)
        size_before = heartbeat.stat().st_size if heartbeat.exists() else 0
        time.sleep(1)
        size_after = heartbeat.stat().st_size if heartbeat.exists() else 0
        value = terminated and empty and size_before > 0 and size_before == size_after
        reason = (
            "verified: Job Object termination stopped the process tree and heartbeat"
            if value
            else "unverified: termination or descendant quiescence was not measurable"
        )
        probe_diagnostics.append(
            {
                "probe": "timeout_terminated",
                "argv": [redact_text(value)[:1000] for value in argv],
                "pid": running.pid,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "timed_out": True,
                "exit_code": running.poll(),
                "stdout": "",
                "stderr": "",
                "final_child_state": "descendant_tree_terminated" if value else "termination_not_proven",
                "child_process_state": "descendant_tree_terminated" if value else "termination_not_proven",
                "heartbeat_bytes_before": size_before,
                "heartbeat_bytes_after": size_after,
                "classification": "verified" if value else "unverified",
                "classification_reason": reason,
            }
        )
        return value if value else None, reason
    except Exception as error:  # noqa: BLE001 - independent probe failure is unverified
        _record_probe_setup_failure(
            probe_diagnostics,
            probe="timeout_terminated",
            started=started,
            error=error,
            argv=argv,
            pid=running.pid,
            child_process_state="process_created_probe_failed",
        )
        return None, "unverified: termination probe failed after launch"
    finally:
        job.terminate()
        job.close()


def _filesystem_limit_probe(
    settings: Settings,
    backend: CodexSandboxBackend,
    root: Path,
    python: str,
    probe_diagnostics: list[dict[str, Any]],
) -> tuple[ProbeCheck, str]:
    started = time.monotonic()
    resource_root = root / "resource"
    command = [
        python,
        "-I",
        "-c",
        (
            "from pathlib import Path;import time;p=Path('resource/grow.bin');"
            "\nwith p.open('wb') as f:"
            "\n for _ in range(1000):f.write(b'x'*262144);f.flush();time.sleep(.05)"
        ),
    ]
    try:
        resource_root.mkdir()
    except Exception as error:  # noqa: BLE001 - setup failure is unverified
        _record_probe_setup_failure(
            probe_diagnostics,
            probe="filesystem_limit_enforced",
            started=started,
            error=error,
            argv=command,
        )
        return None, "unverified: filesystem resource probe setup failed"
    nonce = uuid.uuid4().hex
    launched = _launch_resource_probe(
        settings,
        backend,
        command=command,
        cwd=root,
        environment=_environment(settings, backend, nonce),
        limits=None,
        probe_name="filesystem_limit_enforced",
        probe_diagnostics=probe_diagnostics,
        started=started,
    )
    if launched is None:
        return None, "unverified: filesystem resource probe launch failed"
    writer, job, argv = launched
    detected = False
    writer_empty = False
    final_size = 0
    try:
        identity = capture_process_identity(writer.pid, nonce)
        baseline = process_tree_write_bytes(identity)
        if baseline is None:
            raise RuntimeError("sandbox filesystem write accounting is unavailable")
        admitted_limit = 2 * 1024 * 1024
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and writer.poll() is None:
            usage = scan_directory_bounded(
                resource_root, stop_after_bytes=admitted_limit, stop_after_entries=32
            )
            written = process_tree_write_bytes(identity)
            if written is None:
                raise RuntimeError("sandbox filesystem write accounting became unavailable")
            if usage.total_bytes > admitted_limit or written - baseline > admitted_limit:
                detected = job.terminate()
                break
            time.sleep(0.1)
        writer.wait(timeout=10)
        writer_empty = job.wait_empty(timeout=10)
        final_size = (resource_root / "grow.bin").stat().st_size
        value = detected and writer_empty and final_size < 8 * 1024 * 1024
        reason = (
            "verified: filesystem write bound was detected and the job was drained"
            if value
            else "unverified: filesystem resource boundary was not directly measured"
        )
        probe_diagnostics.append(
            {
                "probe": "filesystem_limit_enforced",
                "argv": [redact_text(value)[:1000] for value in argv],
                "pid": writer.pid,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "timed_out": False,
                "exit_code": writer.returncode,
                "stdout": "",
                "stderr": "",
                "final_child_state": "terminated_at_bound" if detected else "exited",
                "child_process_state": "terminated_at_bound" if detected else "exited",
                "final_size": final_size,
                "classification": "verified" if value else "unverified",
                "classification_reason": reason,
            }
        )
        return value if value else None, reason
    except Exception as error:  # noqa: BLE001 - independent probe failure is unverified
        _record_probe_setup_failure(
            probe_diagnostics,
            probe="filesystem_limit_enforced",
            started=started,
            error=error,
            argv=argv,
            pid=writer.pid,
            child_process_state="process_created_probe_failed",
        )
        return None, "unverified: filesystem resource probe failed after launch"
    finally:
        job.terminate()
        job.close()


def _filesystem_entry_limit_probe(
    settings: Settings,
    backend: CodexSandboxBackend,
    root: Path,
    python: str,
    probe_diagnostics: list[dict[str, Any]],
) -> tuple[ProbeCheck, str]:
    started = time.monotonic()
    entry_root = root / "entries"
    command = [
        python,
        "-I",
        "-c",
        (
            "from pathlib import Path;import time;p=Path('entries');"
            "\nfor i in range(1000):"
            "\n (p/f'{i}.txt').write_text('x');time.sleep(.01)"
        ),
    ]
    try:
        entry_root.mkdir()
    except Exception as error:  # noqa: BLE001 - setup failure is unverified
        _record_probe_setup_failure(
            probe_diagnostics,
            probe="filesystem_entry_limit_enforced",
            started=started,
            error=error,
            argv=command,
        )
        return None, "unverified: filesystem entry probe setup failed"
    nonce = uuid.uuid4().hex
    launched = _launch_resource_probe(
        settings,
        backend,
        command=command,
        cwd=root,
        environment=_environment(settings, backend, nonce),
        limits=None,
        probe_name="filesystem_entry_limit_enforced",
        probe_diagnostics=probe_diagnostics,
        started=started,
    )
    if launched is None:
        return None, "unverified: filesystem entry probe launch failed"
    writer, job, argv = launched
    detected = False
    entry_empty = False
    final_entries = 0
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and writer.poll() is None:
            usage = scan_directory_bounded(
                entry_root, stop_after_bytes=1024 * 1024, stop_after_entries=32
            )
            if usage.entry_count > 32:
                detected = job.terminate()
                break
            time.sleep(0.05)
        writer.wait(timeout=10)
        entry_empty = job.wait_empty(timeout=10)
        final_entries = scan_directory_bounded(
            entry_root, stop_after_bytes=1024 * 1024, stop_after_entries=10_000
        ).entry_count
        value = detected and entry_empty and final_entries < 128
        reason = (
            "verified: filesystem entry bound was detected and the job was drained"
            if value
            else "unverified: filesystem entry boundary was not directly measured"
        )
        probe_diagnostics.append(
            {
                "probe": "filesystem_entry_limit_enforced",
                "argv": [redact_text(value)[:1000] for value in argv],
                "pid": writer.pid,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "timed_out": False,
                "exit_code": writer.returncode,
                "stdout": "",
                "stderr": "",
                "final_child_state": "terminated_at_bound" if detected else "exited",
                "child_process_state": "terminated_at_bound" if detected else "exited",
                "final_entries": final_entries,
                "classification": "verified" if value else "unverified",
                "classification_reason": reason,
            }
        )
        return value if value else None, reason
    except Exception as error:  # noqa: BLE001 - independent probe failure is unverified
        _record_probe_setup_failure(
            probe_diagnostics,
            probe="filesystem_entry_limit_enforced",
            started=started,
            error=error,
            argv=argv,
            pid=writer.pid,
            child_process_state="process_created_probe_failed",
        )
        return None, "unverified: filesystem entry probe failed after launch"
    finally:
        job.terminate()
        job.close()


def _process_limit_probe(
    settings: Settings,
    backend: CodexSandboxBackend,
    root: Path,
    python: str,
    probe_diagnostics: list[dict[str, Any]],
) -> tuple[ProbeCheck, str]:
    started = time.monotonic()
    command = [
        python,
        "-I",
        "-c",
        (
            "import subprocess,sys,time\n"
            'grandchild="import time; time.sleep(60)"\n'
            'child=("import subprocess,sys,time;"'
            "+f\"subprocess.Popen([sys.executable,'-I','-c',{grandchild!r}]);\""
            '+"time.sleep(60)")\n'
            "subprocess.Popen([sys.executable,'-I','-c',child])\n"
            "for _ in range(32):\n"
            " subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(60)'])\n"
            "time.sleep(60)\n"
        ),
    ]
    nonce = uuid.uuid4().hex
    launched = _launch_resource_probe(
        settings,
        backend,
        command=command,
        cwd=root,
        environment=_environment(settings, backend, nonce),
        limits=WindowsJobLimits(max_processes=8, max_memory_bytes=512 * 1024 * 1024),
        probe_name="process_limit_enforced",
        probe_diagnostics=probe_diagnostics,
        started=started,
    )
    if launched is None:
        return None, "unverified: process-limit probe launch failed"
    runner, job, argv = launched
    violation: str | None = None
    empty = False
    try:
        job.violation_event.wait(20)
        violation = job.violation
        job.terminate()
        runner.wait(timeout=10)
        empty = job.wait_empty(timeout=10)
        value = violation == "process_count_limit" and empty and runner.poll() is not None
        reason = (
            "verified: Job Object active-process limit violation was collected"
            if value
            else "unverified: process-count boundary violation was not directly measured"
        )
        probe_diagnostics.append(
            {
                "probe": "process_limit_enforced",
                "argv": [redact_text(value)[:1000] for value in argv],
                "pid": runner.pid,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "timed_out": False,
                "exit_code": runner.returncode,
                "stdout": "",
                "stderr": "",
                "final_child_state": "terminated_and_drained" if empty else "descendants_remaining",
                "child_process_state": "terminated_and_drained" if empty else "descendants_remaining",
                "violation": violation,
                "descendants_remaining": not empty,
                "probe_process_limit": 8,
                "classification": "verified" if value else "unverified",
                "classification_reason": reason,
            }
        )
        return value if value else None, reason
    except Exception as error:  # noqa: BLE001 - independent probe failure is unverified
        _record_probe_setup_failure(
            probe_diagnostics,
            probe="process_limit_enforced",
            started=started,
            error=error,
            argv=argv,
            pid=runner.pid,
            child_process_state="process_created_probe_failed",
        )
        return None, "unverified: process-limit probe failed after launch"
    finally:
        job.terminate()
        job.close()


def _memory_limit_probe(
    settings: Settings,
    backend: CodexSandboxBackend,
    root: Path,
    python: str,
    probe_diagnostics: list[dict[str, Any]],
) -> tuple[ProbeCheck, str]:
    started = time.monotonic()
    grandchild_code = "import time;x=bytearray(96*1024*1024);time.sleep(60)"
    command = [
        python,
        "-I",
        "-c",
        (
            "import subprocess,sys,time;"
            "x=bytearray(96*1024*1024);"
            f"subprocess.Popen([sys.executable,'-I','-c',{grandchild_code!r}]);"
            "time.sleep(60)"
        ),
    ]
    limit = 192 * 1024 * 1024
    nonce = uuid.uuid4().hex
    launched = _launch_resource_probe(
        settings,
        backend,
        command=command,
        cwd=root,
        environment=_environment(settings, backend, nonce),
        limits=WindowsJobLimits(max_processes=16, max_memory_bytes=limit),
        probe_name="memory_limit_enforced",
        probe_diagnostics=probe_diagnostics,
        started=started,
    )
    if launched is None:
        return None, "unverified: memory-limit probe launch failed"
    runner, job, argv = launched
    violation: str | None = None
    empty = False
    accounting: dict[str, int] = {}
    try:
        job.violation_event.wait(20)
        violation = job.violation
        job.terminate()
        runner.wait(timeout=10)
        empty = job.wait_empty(timeout=10)
        accounting = job.accounting()
        value = violation == "process_tree_memory_limit" and empty and runner.poll() is not None
        reason = (
            "verified: Job Object process-tree memory violation was collected"
            if value
            else "unverified: process-tree memory boundary violation was not directly measured"
        )
        probe_diagnostics.append(
            {
                "probe": "memory_limit_enforced",
                "argv": [redact_text(value)[:1000] for value in argv],
                "pid": runner.pid,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "timed_out": False,
                "exit_code": runner.returncode,
                "stdout": "",
                "stderr": "",
                "final_child_state": "terminated_and_drained" if empty else "descendants_remaining",
                "child_process_state": "terminated_and_drained" if empty else "descendants_remaining",
                "violation": violation,
                "descendants_remaining": not empty,
                "probe_memory_limit_bytes": limit,
                **accounting,
                "classification": "verified" if value else "unverified",
                "classification_reason": reason,
            }
        )
        return value if value else None, reason
    except Exception as error:  # noqa: BLE001 - independent probe failure is unverified
        _record_probe_setup_failure(
            probe_diagnostics,
            probe="memory_limit_enforced",
            started=started,
            error=error,
            argv=argv,
            pid=runner.pid,
            child_process_state="process_created_probe_failed",
        )
        return None, "unverified: memory-limit probe failed after launch"
    finally:
        job.terminate()
        job.close()


@_sandbox_verification_serialized
def verify_codex_sandbox_live(
    settings: Settings, *, persist_evidence: bool = True
) -> dict[str, Any]:
    """Exercise the installed Windows sandbox; only complete success creates valid evidence."""
    backend = resolve_codex_sandbox_backend(settings)
    assert settings.sandbox_scratch_dir is not None
    root = settings.sandbox_scratch_dir / "live-verification" / uuid.uuid4().hex
    root.mkdir(parents=True, exist_ok=False)
    checks: dict[str, ProbeCheck] = {}
    diagnostics: dict[str, str] = {}
    check_reasons: dict[str, str] = {}
    probe_diagnostics: list[dict[str, Any]] = []
    version: str | None = None
    guard_implementation: dict[str, Any] | None = None
    guard_verification: GuardVerification | None = None
    python = _python_executable(settings)
    marker = settings.data_dir / "control-plane" / "sandbox-live-verification.json"
    source_canary = settings.workspace_root / f".wlmcp-live-source-{uuid.uuid4().hex}.txt"
    source_write_target = settings.workspace_root / f".wlmcp-live-write-{uuid.uuid4().hex}.txt"
    protected_canary = _protected_information_canary_path(settings.workspace_root)
    outside_canary = Path.home() / f".wlmcp-live-outside-{uuid.uuid4().hex}.txt"
    outside_write_target = Path.home() / f".wlmcp-live-write-{uuid.uuid4().hex}.txt"
    control_read_target = (
        settings.data_dir / "control-plane" / f"live-read-{uuid.uuid4().hex}.json"
    )
    control_write_target = settings.data_dir / "control-plane" / f"live-write-{uuid.uuid4().hex}.txt"
    child_write_target = settings.workspace_root / f".wlmcp-live-child-{uuid.uuid4().hex}.txt"
    grandchild_write_target = (
        settings.workspace_root / f".wlmcp-live-grandchild-{uuid.uuid4().hex}.txt"
    )
    canary_ready: dict[str, bool] = {}

    def prepare_canary(
        name: str, path: Path, content: str, *, remove_after_setup: bool = False
    ) -> None:
        started = time.monotonic()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        except OSError as error:
            canary_ready[name] = False
            diagnostics[name] = redact_text(
                f"probe setup failed: {type(error).__name__}"
            )[:1000]
            _record_probe_setup_failure(
                probe_diagnostics,
                probe=name,
                started=started,
                error=error,
                argv=["host-canary-setup", str(path)],
            )
            return
        canary_ready[name] = True
        if not remove_after_setup:
            return
        try:
            path.unlink(missing_ok=True)
        except OSError as error:
            canary_ready[name] = False
            diagnostics[name] = redact_text(
                f"probe setup cleanup failed: {type(error).__name__}"
            )[:1000]
            _record_probe_setup_failure(
                probe_diagnostics,
                probe=name,
                started=started,
                error=error,
                argv=["host-canary-cleanup", str(path)],
            )

    prepare_canary(
        "source_workspace_read_denied", source_canary, "source-readable-canary"
    )
    prepare_canary(
        "protected_information_denied",
        protected_canary,
        "WLMCP_LIVE_SECRET=canary-only",
    )
    prepare_canary("outside_user_read_denied", outside_canary, "outside-readable-canary")
    prepare_canary(
        "source_workspace_write_denied",
        source_write_target,
        "host-write-canary",
        remove_after_setup=True,
    )
    prepare_canary(
        "outside_user_write_denied",
        outside_write_target,
        "host-write-canary",
        remove_after_setup=True,
    )
    prepare_canary("control_plane_read_denied", control_read_target, "control-read-canary")
    prepare_canary(
        "control_plane_write_denied",
        control_write_target,
        "host-write-canary",
        remove_after_setup=True,
    )
    try:
        with ExitStack() as identity_holds:
            identity_holds.enter_context(hold_codex_sandbox_backend(backend))
            guard_implementation = identity_holds.enter_context(
                hold_wfp_guard_implementation()
            )
            version = probe_codex_version(backend, settings)
            if version != backend.version:
                raise RuntimeError(
                    "Codex backend version changed before live verification"
                )
            # Live verification may recreate exact missing static non-persistent objects.
            # Existing conflicting state still fails closed in the fixed Guard.
            # This explicit verifier is the only production path allowed to request
            # one Guard elevation. Every probe below performs a fresh unelevated
            # read-back and therefore cannot create a repeated UAC loop.
            guard_verification = ensure_runtime_codex_loopback_guard(
                allow_elevation=True
            )
            simple = _run(
                settings,
                backend,
                root,
                [windows_system_executable("cmd.exe"), "/d", "/c", "exit", "0"],
                probe_name="simple_command",
                probe_diagnostics=probe_diagnostics,
            )
            value, reason = _classify_probe_result(
                simple, success=simple.returncode == 0, boundary_escape_code=None
            )
            _set_check(checks, check_reasons, "simple_command", value, reason)
            if value is not True:
                # A fixed `exit 0` failure is a shared Sandbox setup failure, not an
                # independent property result. Stop before another Codex process can
                # repeat the same upstream UAC/setup attempt.
                raise RuntimeError(
                    "foundational Codex Sandbox launch failed; verification stopped "
                    "before additional probes"
                )

            child = _run(
                settings,
                backend,
                root,
                [python, "-I", "-c", "print('child-ok')"],
                probe_name="python_child",
                probe_diagnostics=probe_diagnostics,
            )
            value, reason = _classify_probe_result(
                child,
                success=child.returncode == 0 and b"child-ok" in child.stdout,
                boundary_escape_code=None,
            )
            _set_check(checks, check_reasons, "python_child", value, reason)

            write_result = _run(
                settings,
                backend,
                root,
                [python, "-I", "-c", "from pathlib import Path;Path('result.txt').write_text('result')"],
                probe_name="scratch_write",
                probe_diagnostics=probe_diagnostics,
            )
            try:
                scratch_written = (root / "result.txt").read_text(encoding="utf-8") == "result"
            except OSError as error:
                scratch_written = False
                diagnostics["scratch_write"] = redact_text(
                    f"postcondition read failed: {type(error).__name__}"
                )[:1000]
            value, reason = _classify_probe_result(
                write_result,
                success=scratch_written,
                boundary_escape_code=None,
            )
            _set_check(checks, check_reasons, "scratch_write", value, reason)

            def denied_access_probe(
                name: str, path: Path, operation: str
            ) -> tuple[ProbeCheck, str]:
                if not canary_ready.get(name, True):
                    return None, f"unverified: {name} canary setup failed"
                action = (
                    "p.read_bytes()"
                    if operation == "read"
                    else "p.write_text('sandbox-write-probe')"
                )
                result = _run(
                    settings,
                    backend,
                    root,
                    [
                        python,
                        "-I",
                        "-c",
                        (
                            "import pathlib,sys;"
                            f"p=pathlib.Path({str(path)!r});"
                            f"\ntry:{action}"
                            "\nexcept (OSError,PermissionError):sys.exit(0)"
                            "\nelse:sys.exit(9)"
                        ),
                    ],
                    probe_name=name,
                    probe_diagnostics=probe_diagnostics,
                )
                return _classify_probe_result(
                    result, success=result.returncode == 0
                )

            value, reason = denied_access_probe(
                "source_workspace_read_denied", source_canary, "read"
            )
            _set_check(
                checks, check_reasons, "source_workspace_read_denied", value, reason
            )
            value, reason = denied_access_probe(
                "source_workspace_write_denied", source_write_target, "write"
            )
            _set_check(checks, check_reasons, "source_workspace_write_denied", value, reason)
            value, reason = denied_access_probe(
                "outside_user_read_denied", outside_canary, "read"
            )
            _set_check(checks, check_reasons, "outside_user_read_denied", value, reason)
            value, reason = denied_access_probe(
                "outside_user_write_denied", outside_write_target, "write"
            )
            _set_check(checks, check_reasons, "outside_user_write_denied", value, reason)
            value, reason = denied_access_probe(
                "protected_information_denied", protected_canary, "read"
            )
            _set_check(checks, check_reasons, "protected_information_denied", value, reason)

            value, reason = denied_access_probe(
                "control_plane_read_denied", control_read_target, "read"
            )
            _set_check(checks, check_reasons, "control_plane_read_denied", value, reason)
            value, reason = denied_access_probe(
                "control_plane_write_denied", control_write_target, "write"
            )
            _set_check(checks, check_reasons, "control_plane_write_denied", value, reason)

            internet_host = "1.1.1.1"
            internet_port = 443
            control_started = time.monotonic()
            internet_control_reachable = _host_endpoint_reachable(
                internet_host, internet_port
            )
            checks["internet_control_reachable"] = internet_control_reachable
            probe_diagnostics.append(
                {
                    "probe": "internet_control_reachable",
                    "pid": None,
                    "argv": [],
                    "endpoint": f"{internet_host}:{internet_port}",
                    "elapsed_seconds": round(time.monotonic() - control_started, 3),
                    "timed_out": False,
                    "exit_code": None,
                    "stdout": "",
                    "stderr": "",
                    "child_process_state": "host_control_completed",
                    "final_child_state": "host_control_completed",
                    "reachable": internet_control_reachable,
                    "classification": "executed" if internet_control_reachable else "unverified",
                    "classification_reason": (
                        "host control endpoint reachable"
                        if internet_control_reachable
                        else "unverified: host control endpoint unavailable"
                    ),
                }
            )
            if internet_control_reachable:
                network_result = _run(
                    settings,
                    backend,
                    root,
                    [
                        python,
                        "-I",
                        "-c",
                        (
                            "import socket,sys;s=socket.socket();s.settimeout(2);"
                            f"\ntry:s.connect(({internet_host!r},{internet_port}))"
                            "\nexcept OSError:sys.exit(0)"
                            "\nelse:sys.exit(9)"
                        ),
                    ],
                    probe_name="internet_denied",
                    probe_diagnostics=probe_diagnostics,
                )
                value, reason = _classify_probe_result(
                    network_result, success=network_result.returncode == 0
                )
                _set_check(checks, check_reasons, "internet_denied", value, reason)
            else:
                diagnostics["internet_denied"] = (
                    "probe unavailable: host control could not connect to "
                    f"{internet_host}:{internet_port}"
                )
                _set_check(
                    checks,
                    check_reasons,
                    "internet_denied",
                    None,
                    "unverified: host control could not establish the Internet listener",
                )

            def listener_probe(name: str, host: str) -> tuple[ProbeCheck, str]:
                started = time.monotonic()
                listener: socket.socket | None = None
                try:
                    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    listener.bind((host, 0))
                    listener.listen(1)
                    port = int(listener.getsockname()[1])
                    result = _run(
                        settings,
                        backend,
                        root,
                        [
                            python,
                            "-I",
                            "-c",
                            (
                                "import socket,sys;s=socket.socket();s.settimeout(2);"
                                f"\ntry:s.connect(({host!r},{port}))"
                                "\nexcept OSError:sys.exit(0)"
                                "\nelse:sys.exit(9)"
                            ),
                        ],
                        probe_name=name,
                        probe_diagnostics=probe_diagnostics,
                    )
                    return _classify_probe_result(
                        result, success=result.returncode == 0
                    )
                except Exception as error:  # noqa: BLE001 - this probe is independent
                    _record_probe_setup_failure(
                        probe_diagnostics,
                        probe=name,
                        started=started,
                        error=error,
                        error_key="listener_error",
                    )
                    return None, "unverified: listener creation or probe setup failed"
                finally:
                    if listener is not None:
                        listener.close()

            value, reason = listener_probe("loopback_denied", "127.0.0.1")
            _set_check(checks, check_reasons, "loopback_denied", value, reason)
            lan_address: str | None = None
            try:
                route_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    route_probe.connect(("1.1.1.1", 53))
                    lan_address = str(route_probe.getsockname()[0])
                finally:
                    route_probe.close()
                if lan_address.startswith("127.") or lan_address == "0.0.0.0":
                    raise OSError("no non-loopback IPv4 address is available")
            except OSError as error:
                message = f"probe unavailable: {type(error).__name__}"
                diagnostics["lan_denied"] = message
                _set_check(
                    checks,
                    check_reasons,
                    "lan_denied",
                    None,
                    "unverified: no non-loopback listener could be prepared",
                )
            else:
                value, reason = listener_probe("lan_denied", lan_address)
                _set_check(checks, check_reasons, "lan_denied", value, reason)

            descendant_check_names = (
                "source_workspace_read_denied",
                "source_workspace_write_denied",
                "outside_user_read_denied",
                "protected_information_denied",
                "control_plane_read_denied",
                "control_plane_write_denied",
                "internet_denied",
                "lan_denied",
                "loopback_denied",
            )
            descendant_listeners: list[socket.socket] = []
            try:
                loopback_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                loopback_listener.bind(("127.0.0.1", 0))
                loopback_listener.listen(4)
                descendant_listeners.append(loopback_listener)
                loopback_endpoint = (
                    "127.0.0.1",
                    int(loopback_listener.getsockname()[1]),
                )
                lan_endpoint: tuple[str, int] | None = None
                if lan_address is not None:
                    lan_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    lan_listener.bind((lan_address, 0))
                    lan_listener.listen(4)
                    descendant_listeners.append(lan_listener)
                    lan_endpoint = (lan_address, int(lan_listener.getsockname()[1]))

                def descendant_boundary_code(write_target: Path) -> str:
                    filesystem = {
                        "source_workspace_read_denied": ("read", str(source_canary)),
                        "source_workspace_write_denied": ("write", str(write_target)),
                        "outside_user_read_denied": ("read", str(outside_canary)),
                        "protected_information_denied": (
                            "read",
                            str(protected_canary),
                        ),
                        "control_plane_read_denied": ("read", str(control_read_target)),
                        "control_plane_write_denied": (
                            "write",
                            str(control_write_target),
                        ),
                    }
                    endpoints: dict[str, tuple[str, int]] = {}
                    if loopback_endpoint is not None:
                        endpoints["loopback_denied"] = loopback_endpoint
                    if internet_control_reachable:
                        endpoints["internet_denied"] = (internet_host, internet_port)
                    if lan_endpoint is not None:
                        endpoints["lan_denied"] = lan_endpoint
                    return (
                        "import json,pathlib,socket\n"
                        f"filesystem={filesystem!r}\n"
                        f"endpoints={endpoints!r}\n"
                        "results={}\n"
                        "for name,(operation,value) in filesystem.items():\n"
                        " p=pathlib.Path(value)\n"
                        " try:\n"
                        "  p.read_bytes() if operation=='read' else p.write_text('escape')\n"
                        " except (OSError,PermissionError): results[name]=True\n"
                        " else: results[name]=False\n"
                        "for name,(host,port) in endpoints.items():\n"
                        " s=socket.socket();s.settimeout(2)\n"
                        " try: s.connect((host,port))\n"
                        " except OSError: results[name]=True\n"
                        " else: results[name]=False\n"
                        " finally: s.close()\n"
                        "print(json.dumps(results,sort_keys=True))\n"
                    )

                def record_descendant(
                    prefix: str, result: subprocess.CompletedProcess[bytes]
                ) -> None:
                    try:
                        payload = json.loads(result.stdout.decode("utf-8").strip().splitlines()[-1])
                    except (IndexError, UnicodeDecodeError, json.JSONDecodeError) as error:
                        diagnostics[f"{prefix}_boundary"] = (
                            f"invalid descendant probe output: {type(error).__name__}"
                        )
                        reason = "unverified: descendant probe output was not measurable"
                        if result.returncode in {
                            _LAUNCH_FAILURE_RETURN_CODE,
                            _TIMEOUT_RETURN_CODE,
                            _PROBE_ERROR_RETURN_CODE,
                        }:
                            reason = _return_code_reason(result.returncode)
                        for name in descendant_check_names:
                            _set_check(checks, check_reasons, f"{prefix}_{name}", None, reason)
                        return
                    for name in descendant_check_names:
                        full_name = f"{prefix}_{name}"
                        if not canary_ready.get(name, True):
                            _set_check(
                                checks,
                                check_reasons,
                                full_name,
                                None,
                                f"unverified: {name} canary setup failed",
                            )
                        elif result.returncode != 0:
                            _set_check(
                                checks,
                                check_reasons,
                                full_name,
                                None,
                                _return_code_reason(result.returncode),
                            )
                        elif name not in payload:
                            _set_check(
                                checks,
                                check_reasons,
                                full_name,
                                None,
                                "unverified: descendant probe endpoint was unavailable",
                            )
                        elif payload[name] is True:
                            _set_check(
                                checks,
                                check_reasons,
                                full_name,
                                True,
                                "verified: descendant inherited the requested denial",
                            )
                        else:
                            _set_check(
                                checks,
                                check_reasons,
                                full_name,
                                False,
                                "failed: descendant observed a boundary escape",
                            )

                try:
                    child_direct = _run(
                        settings,
                        backend,
                        root,
                        [python, "-I", "-c", descendant_boundary_code(child_write_target)],
                        probe_name="child_boundary_inherited",
                        probe_diagnostics=probe_diagnostics,
                    )
                    record_descendant("child", child_direct)
                except Exception as error:  # noqa: BLE001 - continue independent probes
                    diagnostics["child_boundary"] = redact_text(f"{type(error).__name__}: {error}")[
                        :1000
                    ]
                    for name in descendant_check_names:
                        _set_check(
                            checks,
                            check_reasons,
                            f"child_{name}",
                            None,
                            "unverified: child descendant probe could not run",
                        )

                grandchild_code = descendant_boundary_code(grandchild_write_target)
                child_code = (
                    "import subprocess,sys;"
                    "result=subprocess.run([sys.executable,'-I','-c',"
                    f"{grandchild_code!r}],capture_output=True);"
                    "sys.stdout.buffer.write(result.stdout);sys.exit(result.returncode)"
                )
                try:
                    descendant = _run(
                        settings,
                        backend,
                        root,
                        [python, "-I", "-c", child_code],
                        probe_name="grandchild_boundary_inherited",
                        probe_diagnostics=probe_diagnostics,
                    )
                    record_descendant("grandchild", descendant)
                except Exception as error:  # noqa: BLE001 - continue independent probes
                    diagnostics["grandchild_boundary"] = redact_text(
                        f"{type(error).__name__}: {error}"
                    )[:1000]
                    for name in descendant_check_names:
                        _set_check(
                            checks,
                            check_reasons,
                            f"grandchild_{name}",
                            None,
                            "unverified: grandchild descendant probe could not run",
                        )
            except Exception as error:  # noqa: BLE001 - dependent setup must not stop later probes
                diagnostics["descendant_boundary_setup"] = redact_text(
                    f"{type(error).__name__}: {error}"
                )[:1000]
                _record_probe_setup_failure(
                    probe_diagnostics,
                    probe="descendant_boundary_setup",
                    started=time.monotonic(),
                    error=error,
                )
                for prefix in ("child", "grandchild"):
                    for name in descendant_check_names:
                        _set_check(
                            checks,
                            check_reasons,
                            f"{prefix}_{name}",
                            None,
                            "unverified: descendant listener setup failed",
                        )
            finally:
                for listener in descendant_listeners:
                    listener.close()

            value, reason = _termination_probe(
                settings, backend, root, python, probe_diagnostics
            )
            _set_check(checks, check_reasons, "timeout_terminated", value, reason)

            value, reason = _filesystem_limit_probe(
                settings, backend, root, python, probe_diagnostics
            )
            _set_check(
                checks, check_reasons, "filesystem_limit_enforced", value, reason
            )

            value, reason = _filesystem_entry_limit_probe(
                settings, backend, root, python, probe_diagnostics
            )
            _set_check(
                checks, check_reasons, "filesystem_entry_limit_enforced", value, reason
            )

            value, reason = _process_limit_probe(
                settings, backend, root, python, probe_diagnostics
            )
            _set_check(checks, check_reasons, "process_limit_enforced", value, reason)

            value, reason = _memory_limit_probe(
                settings, backend, root, python, probe_diagnostics
            )
            _set_check(checks, check_reasons, "memory_limit_enforced", value, reason)

            for name, passed in checks.items():
                if passed is not True:
                    diagnostics.setdefault(
                        name,
                        check_reasons.get(name, "unverified: probe did not verify the boundary"),
                    )
            properties = _property_results(checks, check_reasons)
            result = {
                **_c7_marker_identity(
                    settings,
                    backend,
                    backend_version=version,
                    guard_implementation=guard_implementation,
                    guard_verification=guard_verification,
                ),
                "verified_at": utc_now_iso(),
                "checks": checks,
                "properties": properties,
                "passed": all(
                    item["status"] == "verified" for item in properties.values()
                ),
                "diagnostics": diagnostics,
                "probe_diagnostics": probe_diagnostics,
            }
            if persist_evidence:
                _write_evidence(marker, result)
            return result
    except Exception as error:  # noqa: BLE001 - unavailable evidence must be durable and explicit
        _set_check(
            checks,
            check_reasons,
            "simple_command",
            checks.get("simple_command"),
            check_reasons.get("simple_command", "unverified: live verification aborted"),
        )
        diagnostics["verification_error"] = redact_text(
            f"{type(error).__name__}: {error}"
        )[:2000]
        properties = _property_results(checks, check_reasons)
        result = {
            **_c7_marker_identity(
                settings,
                backend,
                backend_version=version,
                guard_implementation=guard_implementation,
                guard_verification=guard_verification,
            ),
            "verified_at": utc_now_iso(),
            "checks": checks,
            "properties": properties,
            "passed": False,
            "diagnostics": diagnostics,
            "probe_diagnostics": probe_diagnostics,
        }
        if persist_evidence:
            _write_evidence(marker, result)
        return result
    finally:
        for path in (
            source_canary,
            source_write_target,
            protected_canary,
            outside_canary,
            outside_write_target,
            control_read_target,
            control_write_target,
            child_write_target,
            grandchild_write_target,
        ):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            protected_canary.parent.rmdir()
        except OSError:
            pass
        shutil.rmtree(root, ignore_errors=True)
