from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import uuid
from functools import wraps
from pathlib import Path
from typing import Any

from .child_env import build_command_environment, sanitize_executable_search_path
from .config import Settings
from .process_utils import (
    capture_process_identity,
    creation_flags,
    process_tree_write_bytes,
    terminate_process_tree,
)
from .redaction import redact_text
from .resources import NamedControlPlaneLock, scan_directory_bounded
from .sandbox_backend import (
    SANDBOX_SECURITY_PROPERTIES,
    CodexSandboxBackend,
    build_codex_sandbox_argv,
    hold_codex_sandbox_backend,
    probe_codex_version,
    resolve_codex_sandbox_backend,
)
from .util import canonical_json, sha256_text, utc_now_iso
from .windows_system import windows_system_executable


def _sandbox_verification_serialized(function: Any) -> Any:
    @wraps(function)
    def locked(settings: Settings, *args: Any, **kwargs: Any) -> Any:
        with NamedControlPlaneLock(settings, "sandbox-verification", timeout=180):
            return function(settings, *args, **kwargs)

    return locked


def _write_evidence(marker: Path, result: dict[str, Any]) -> None:
    temporary_marker = marker.with_name(f".{marker.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary_marker.write_text(canonical_json(result), encoding="utf-8")
        os.replace(temporary_marker, marker)
    finally:
        temporary_marker.unlink(missing_ok=True)


def _property_results(checks: dict[str, bool]) -> dict[str, dict[str, Any]]:
    """Translate concrete probes into contract-level properties without overclaiming."""
    requirements = {
        "filesystem_read": ("source_read", "outside_user_read_denied"),
        "filesystem_write": (
            "scratch_write",
            "source_workspace_write_denied",
            "control_plane_write_denied",
        ),
        "protected_information_read": ("protected_information_denied",),
        "internet": ("internet_denied",),
        "lan": ("lan_denied",),
        "loopback": ("loopback_denied",),
        "descendant_containment": ("grandchild_boundary_inherited",),
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
        missing = [name for name in required if checks.get(name) is not True]
        result[property_name] = {
            "status": "verified" if not missing else "unverified",
            "checks": list(required),
            "missing_or_failed": missing,
        }
    return result


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
) -> subprocess.CompletedProcess[bytes]:
    nonce = uuid.uuid4().hex
    argv = build_codex_sandbox_argv(backend, command=command, cwd=str(cwd))
    process = subprocess.Popen(
        argv,
        cwd=Path(backend.executable).parent,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        creationflags=creation_flags(),
        env=_environment(settings, backend, nonce),
    )
    identity = capture_process_identity(process.pid, nonce)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        if not terminate_process_tree(identity):
            process.kill()
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired as cleanup_error:
            process.kill()
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            raise RuntimeError(
                "timed-out sandbox verification process tree could not be drained"
            ) from cleanup_error
        raise subprocess.TimeoutExpired(argv, timeout) from error
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


@_sandbox_verification_serialized
def verify_codex_sandbox_live(settings: Settings) -> dict[str, Any]:
    """Exercise the installed Windows sandbox; only complete success creates valid evidence."""
    backend = resolve_codex_sandbox_backend(settings)
    assert settings.sandbox_scratch_dir is not None
    root = settings.sandbox_scratch_dir / "live-verification" / uuid.uuid4().hex
    root.mkdir(parents=True, exist_ok=False)
    checks: dict[str, bool] = {}
    diagnostics: dict[str, str] = {}
    version: str | None = None
    python = _python_executable(settings)
    marker = settings.data_dir / "control-plane" / "sandbox-live-verification.json"
    try:
        with hold_codex_sandbox_backend(backend):
            version = probe_codex_version(backend, settings)
            simple = _run(
                settings,
                backend,
                root,
                [windows_system_executable("cmd.exe"), "/d", "/c", "exit", "0"],
            )
            checks["simple_command"] = simple.returncode == 0

            child = _run(settings, backend, root, [python, "-I", "-c", "print('child-ok')"])
            checks["python_child"] = child.returncode == 0 and b"child-ok" in child.stdout

            source = root / "source.txt"
            source.write_text("bound-source", encoding="utf-8")
            source_result = _run(
                settings,
                backend,
                root,
                [python, "-I", "-c", "from pathlib import Path;print(Path('source.txt').read_text())"],
            )
            checks["source_read"] = source_result.returncode == 0 and b"bound-source" in source_result.stdout

            write_result = _run(
                settings,
                backend,
                root,
                [python, "-I", "-c", "from pathlib import Path;Path('result.txt').write_text('result')"],
            )
            checks["scratch_write"] = (
                write_result.returncode == 0
                and (root / "result.txt").read_text(encoding="utf-8") == "result"
            )

            control_target = settings.data_dir / "control-plane" / "namespace.json"
            control_result = _run(
                settings,
                backend,
                root,
                [
                    python,
                    "-I",
                    "-c",
                    (
                        "import pathlib,sys;"
                        f"p=pathlib.Path({str(control_target)!r});"
                        "\ntry:p.read_bytes()"
                        "\nexcept (OSError,PermissionError):sys.exit(0)"
                        "\nelse:sys.exit(9)"
                    ),
                ],
            )
            checks["control_plane_denied"] = control_result.returncode == 0

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
                        "\ntry:s.connect(('1.1.1.1',443))"
                        "\nexcept OSError:sys.exit(0)"
                        "\nelse:sys.exit(9)"
                    ),
                ],
            )
            checks["network_denied"] = network_result.returncode == 0

            grandchild_code = (
                "from pathlib import Path;"
                "Path('grandchild.txt').write_text('contained')"
            )
            child_code = (
                "import subprocess,sys;"
                f"subprocess.check_call([sys.executable,'-I','-c',{grandchild_code!r}])"
            )
            parent_code = (
                "import subprocess,sys;"
                f"subprocess.check_call([sys.executable,'-I','-c',{child_code!r}])"
            )
            descendant = _run(
                settings,
                backend,
                root,
                [
                    python,
                    "-I",
                    "-c",
                    parent_code,
                ],
            )
            checks["grandchild_contained"] = (
                descendant.returncode == 0 and (root / "grandchild.txt").is_file()
            )

            nonce = uuid.uuid4().hex
            heartbeat = root / "heartbeat.bin"
            heartbeat_code = (
                "from pathlib import Path\n"
                "import time\n"
                "path=Path('heartbeat.bin')\n"
                "while True:\n"
                " with path.open('ab') as output: output.write(b'x')\n"
                " time.sleep(.1)\n"
            )
            timeout_parent_code = (
                "import subprocess,sys,time;"
                f"subprocess.Popen([sys.executable,'-I','-c',{heartbeat_code!r}]);"
                "time.sleep(60)"
            )
            timeout_command = [
                python,
                "-I",
                "-c",
                timeout_parent_code,
            ]
            running = subprocess.Popen(
                build_codex_sandbox_argv(backend, command=timeout_command, cwd=str(root)),
                cwd=Path(backend.executable).parent,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                creationflags=creation_flags(),
                env=_environment(settings, backend, nonce),
            )
            identity = capture_process_identity(running.pid, nonce)
            time.sleep(2)
            terminated = terminate_process_tree(identity)
            size_before = heartbeat.stat().st_size if heartbeat.exists() else 0
            time.sleep(1)
            size_after = heartbeat.stat().st_size if heartbeat.exists() else 0
            checks["timeout_terminated"] = terminated and size_before == size_after

            resource_root = root / "resource"
            resource_root.mkdir()
            nonce = uuid.uuid4().hex
            writer = subprocess.Popen(
                build_codex_sandbox_argv(
                    backend,
                    command=[
                        python,
                        "-I",
                        "-c",
                        (
                            "from pathlib import Path;import time;p=Path('resource/grow.bin');"
                            "\nwith p.open('wb') as f:"
                            "\n for _ in range(1000):f.write(b'x'*262144);f.flush();time.sleep(.05)"
                        ),
                    ],
                    cwd=str(root),
                ),
                cwd=Path(backend.executable).parent,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                creationflags=creation_flags(),
                env=_environment(settings, backend, nonce),
            )
            writer_identity = capture_process_identity(writer.pid, nonce)
            write_baseline = process_tree_write_bytes(writer_identity)
            if write_baseline is None:
                raise RuntimeError("sandbox filesystem write accounting is unavailable")
            admitted_limit = 2 * 1024 * 1024
            detected = False
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and writer.poll() is None:
                usage = scan_directory_bounded(
                    resource_root,
                    stop_after_bytes=admitted_limit,
                    stop_after_entries=32,
                )
                written = process_tree_write_bytes(writer_identity)
                if written is None:
                    raise RuntimeError("sandbox filesystem write accounting became unavailable")
                if (
                    usage.total_bytes > admitted_limit
                    or written - write_baseline > admitted_limit
                ):
                    detected = terminate_process_tree(writer_identity)
                    break
                time.sleep(0.1)
            writer.wait(timeout=10)
            final_size = (resource_root / "grow.bin").stat().st_size
            checks["filesystem_limit_enforced"] = detected and final_size < 8 * 1024 * 1024
            if not checks["filesystem_limit_enforced"]:
                diagnostics["filesystem_limit_enforced"] = (
                    f"detected={detected}; final_size={final_size}; "
                    f"launcher_returncode={writer.returncode}"
                )

            for name, passed in checks.items():
                if not passed:
                    diagnostics.setdefault(name, "live check failed")
            properties = _property_results(checks)
            result = {
                "version": 2,
                "verified_at": utc_now_iso(),
                "backend_digest": sha256_text(canonical_json(backend.as_dict())),
                "backend_version": version,
                "checks": checks,
                "properties": properties,
                "passed": all(
                    item["status"] == "verified" for item in properties.values()
                ),
                "diagnostics": diagnostics,
            }
            _write_evidence(marker, result)
            return result
    except Exception as error:  # noqa: BLE001 - unavailable evidence must be durable and explicit
        checks.setdefault("simple_command", False)
        diagnostics["verification_error"] = redact_text(
            f"{type(error).__name__}: {error}"
        )[:2000]
        properties = _property_results(checks)
        result = {
            "version": 2,
            "verified_at": utc_now_iso(),
            "backend_digest": sha256_text(canonical_json(backend.as_dict())),
            "backend_version": version,
            "checks": checks,
            "properties": properties,
            "passed": False,
            "diagnostics": diagnostics,
        }
        _write_evidence(marker, result)
        return result
    finally:
        shutil.rmtree(root, ignore_errors=True)
