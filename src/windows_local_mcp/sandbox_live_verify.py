from __future__ import annotations

import os
import shutil
import socket
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


def _protected_information_canary_path(workspace_root: Path) -> Path:
    return workspace_root / f".wlmcp-live-protected-{uuid.uuid4().hex}" / ".env"


def _host_endpoint_reachable(host: str, port: int, *, timeout: float = 2) -> bool:
    try:
        connection = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return False
    connection.close()
    return True


def _property_results(checks: dict[str, bool]) -> dict[str, dict[str, Any]]:
    """Translate concrete probes into contract-level properties without overclaiming."""
    requirements = {
        "filesystem_read": (
            "source_read",
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
            "child_boundary_inherited",
            "grandchild_boundary_inherited",
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
        unverified = [name for name in required if name not in checks]
        incomplete = [name for name in required if checks.get(name) is not True]
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
    probe_name: str | None = None,
    probe_diagnostics: list[dict[str, Any]] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    nonce = uuid.uuid4().hex
    argv = build_codex_sandbox_argv(backend, command=command, cwd=str(cwd))
    started = time.monotonic()
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
    diagnostic = {
        "probe": probe_name or "unnamed",
        "argv": [redact_text(value)[:1000] for value in argv],
        "pid": process.pid,
    }
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        diagnostic.update(
            {
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "timed_out": True,
                "child_process_state": "termination_requested",
            }
        )
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
        diagnostic.update(
            {
                "exit_code": process.returncode,
                "child_process_state": "terminated_and_drained",
            }
        )
        if probe_diagnostics is not None:
            probe_diagnostics.append(diagnostic)
        raise subprocess.TimeoutExpired(argv, timeout) from error
    diagnostic.update(
        {
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "timed_out": False,
            "exit_code": process.returncode,
            "stdout": redact_text(stdout.decode("utf-8", errors="replace"))[:2000],
            "stderr": redact_text(stderr.decode("utf-8", errors="replace"))[:2000],
            "child_process_state": "exited_and_drained",
        }
    )
    if probe_diagnostics is not None:
        probe_diagnostics.append(diagnostic)
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
    probe_diagnostics: list[dict[str, Any]] = []
    version: str | None = None
    python = _python_executable(settings)
    marker = settings.data_dir / "control-plane" / "sandbox-live-verification.json"
    source_canary = settings.workspace_root / f".wlmcp-live-source-{uuid.uuid4().hex}.txt"
    source_write_target = settings.workspace_root / f".wlmcp-live-write-{uuid.uuid4().hex}.txt"
    protected_canary = _protected_information_canary_path(settings.workspace_root)
    outside_canary = Path.home() / f".wlmcp-live-outside-{uuid.uuid4().hex}.txt"
    outside_write_target = Path.home() / f".wlmcp-live-write-{uuid.uuid4().hex}.txt"
    control_write_target = settings.data_dir / "control-plane" / f"live-write-{uuid.uuid4().hex}.txt"
    child_write_target = settings.workspace_root / f".wlmcp-live-child-{uuid.uuid4().hex}.txt"
    grandchild_write_target = (
        settings.workspace_root / f".wlmcp-live-grandchild-{uuid.uuid4().hex}.txt"
    )
    try:
        source_canary.write_text("source-readable-canary", encoding="utf-8")
        protected_canary.parent.mkdir()
        protected_canary.write_text("WLMCP_LIVE_SECRET=canary-only", encoding="utf-8")
        outside_canary.write_text("outside-readable-canary", encoding="utf-8")
        with hold_codex_sandbox_backend(backend):
            version = probe_codex_version(backend, settings)
            simple = _run(
                settings,
                backend,
                root,
                [windows_system_executable("cmd.exe"), "/d", "/c", "exit", "0"],
                probe_name="simple_command",
                probe_diagnostics=probe_diagnostics,
            )
            checks["simple_command"] = simple.returncode == 0

            child = _run(
                settings,
                backend,
                root,
                [python, "-I", "-c", "print('child-ok')"],
                probe_name="python_child",
                probe_diagnostics=probe_diagnostics,
            )
            checks["python_child"] = child.returncode == 0 and b"child-ok" in child.stdout

            source_result = _run(
                settings,
                backend,
                root,
                [
                    python,
                    "-I",
                    "-c",
                    f"from pathlib import Path;print(Path({str(source_canary)!r}).read_text())",
                ],
                probe_name="source_read",
                probe_diagnostics=probe_diagnostics,
            )
            checks["source_read"] = (
                source_result.returncode == 0
                and b"source-readable-canary" in source_result.stdout
            )

            write_result = _run(
                settings,
                backend,
                root,
                [python, "-I", "-c", "from pathlib import Path;Path('result.txt').write_text('result')"],
                probe_name="scratch_write",
                probe_diagnostics=probe_diagnostics,
            )
            checks["scratch_write"] = (
                write_result.returncode == 0
                and (root / "result.txt").read_text(encoding="utf-8") == "result"
            )

            def denied_access_probe(name: str, path: Path, operation: str) -> bool:
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
                return result.returncode == 0

            checks["source_workspace_write_denied"] = denied_access_probe(
                "source_workspace_write_denied", source_write_target, "write"
            )
            checks["outside_user_read_denied"] = denied_access_probe(
                "outside_user_read_denied", outside_canary, "read"
            )
            checks["outside_user_write_denied"] = denied_access_probe(
                "outside_user_write_denied", outside_write_target, "write"
            )
            checks["protected_information_denied"] = denied_access_probe(
                "protected_information_denied", protected_canary, "read"
            )

            control_target = settings.data_dir / "control-plane" / "namespace.json"
            checks["control_plane_read_denied"] = denied_access_probe(
                "control_plane_read_denied", control_target, "read"
            )
            checks["control_plane_write_denied"] = denied_access_probe(
                "control_plane_write_denied", control_write_target, "write"
            )

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
                    "endpoint": f"{internet_host}:{internet_port}",
                    "elapsed_seconds": round(time.monotonic() - control_started, 3),
                    "reachable": internet_control_reachable,
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
                checks["internet_denied"] = network_result.returncode == 0
            else:
                diagnostics["internet_denied"] = (
                    "probe unavailable: host control could not connect to "
                    f"{internet_host}:{internet_port}"
                )

            def listener_probe(name: str, host: str) -> bool:
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
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
                    return result.returncode == 0
                finally:
                    listener.close()

            checks["loopback_denied"] = listener_probe("loopback_denied", "127.0.0.1")
            try:
                route_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    route_probe.connect(("1.1.1.1", 53))
                    lan_address = str(route_probe.getsockname()[0])
                finally:
                    route_probe.close()
                if lan_address.startswith("127.") or lan_address == "0.0.0.0":
                    raise OSError("no non-loopback IPv4 address is available")
                checks["lan_denied"] = listener_probe("lan_denied", lan_address)
            except OSError as error:
                diagnostics["lan_denied"] = f"probe unavailable: {type(error).__name__}"

            def descendant_boundary_code(write_target: Path) -> str:
                return (
                    "from pathlib import Path\n"
                    "import sys\n"
                    "ok=True\n"
                    f"write_target=Path({str(write_target)!r})\n"
                    f"secret=Path({str(protected_canary)!r})\n"
                    "try: write_target.write_text('boundary-escape')\n"
                    "except (OSError,PermissionError): pass\n"
                    "else: ok=False\n"
                    "try: secret.read_bytes()\n"
                    "except (OSError,PermissionError): pass\n"
                    "else: ok=False\n"
                    "sys.exit(0 if ok else 9)\n"
                )

            child_direct = _run(
                settings,
                backend,
                root,
                [python, "-I", "-c", descendant_boundary_code(child_write_target)],
                probe_name="child_boundary_inherited",
                probe_diagnostics=probe_diagnostics,
            )
            checks["child_boundary_inherited"] = child_direct.returncode == 0

            grandchild_code = descendant_boundary_code(grandchild_write_target)
            child_code = (
                "import subprocess,sys;"
                f"subprocess.check_call([sys.executable,'-I','-c',{grandchild_code!r}])"
            )
            descendant = _run(
                settings,
                backend,
                root,
                [
                    python,
                    "-I",
                    "-c",
                    child_code,
                ],
                probe_name="grandchild_boundary_inherited",
                probe_diagnostics=probe_diagnostics,
            )
            checks["grandchild_boundary_inherited"] = descendant.returncode == 0

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
            timeout_argv = build_codex_sandbox_argv(
                backend, command=timeout_command, cwd=str(root)
            )
            timeout_started = time.monotonic()
            running = subprocess.Popen(
                timeout_argv,
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
            probe_diagnostics.append(
                {
                    "probe": "timeout_terminated",
                    "argv": [redact_text(value)[:1000] for value in timeout_argv],
                    "pid": running.pid,
                    "elapsed_seconds": round(time.monotonic() - timeout_started, 3),
                    "timed_out": True,
                    "exit_code": running.poll(),
                    "child_process_state": (
                        "descendant_tree_terminated"
                        if checks["timeout_terminated"]
                        else "termination_not_proven"
                    ),
                }
            )

            resource_root = root / "resource"
            resource_root.mkdir()
            nonce = uuid.uuid4().hex
            writer_argv = build_codex_sandbox_argv(
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
            )
            writer_started = time.monotonic()
            writer = subprocess.Popen(
                writer_argv,
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
            probe_diagnostics.append(
                {
                    "probe": "filesystem_limit_enforced",
                    "argv": [redact_text(value)[:1000] for value in writer_argv],
                    "pid": writer.pid,
                    "elapsed_seconds": round(time.monotonic() - writer_started, 3),
                    "exit_code": writer.returncode,
                    "child_process_state": "terminated_at_bound" if detected else "exited",
                    "final_size": final_size,
                }
            )

            entry_root = root / "entries"
            entry_root.mkdir()
            nonce = uuid.uuid4().hex
            entry_argv = build_codex_sandbox_argv(
                backend,
                command=[
                    python,
                    "-I",
                    "-c",
                    (
                        "from pathlib import Path;import time;p=Path('entries');"
                        "\nfor i in range(1000):"
                        "\n (p/f'{i}.txt').write_text('x');time.sleep(.01)"
                    ),
                ],
                cwd=str(root),
            )
            entry_started = time.monotonic()
            entry_writer = subprocess.Popen(
                entry_argv,
                cwd=Path(backend.executable).parent,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                creationflags=creation_flags(),
                env=_environment(settings, backend, nonce),
            )
            entry_identity = capture_process_identity(entry_writer.pid, nonce)
            entry_detected = False
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and entry_writer.poll() is None:
                usage = scan_directory_bounded(
                    entry_root,
                    stop_after_bytes=1024 * 1024,
                    stop_after_entries=32,
                )
                if usage.entry_count > 32:
                    entry_detected = terminate_process_tree(entry_identity)
                    break
                time.sleep(0.05)
            entry_writer.wait(timeout=10)
            final_entries = scan_directory_bounded(
                entry_root,
                stop_after_bytes=1024 * 1024,
                stop_after_entries=10_000,
            ).entry_count
            checks["filesystem_entry_limit_enforced"] = (
                entry_detected and final_entries < 128
            )
            if not checks["filesystem_entry_limit_enforced"]:
                diagnostics["filesystem_entry_limit_enforced"] = (
                    f"detected={entry_detected}; final_entries={final_entries}; "
                    f"launcher_returncode={entry_writer.returncode}"
                )
            probe_diagnostics.append(
                {
                    "probe": "filesystem_entry_limit_enforced",
                    "argv": [redact_text(value)[:1000] for value in entry_argv],
                    "pid": entry_writer.pid,
                    "elapsed_seconds": round(time.monotonic() - entry_started, 3),
                    "exit_code": entry_writer.returncode,
                    "child_process_state": (
                        "terminated_at_bound" if entry_detected else "exited"
                    ),
                    "final_entries": final_entries,
                }
            )

            diagnostics["process_limit_enforced"] = (
                "no per-Sandbox descendant process-count runtime bound is implemented"
            )
            diagnostics["memory_limit_enforced"] = (
                "no per-Sandbox process-tree memory runtime bound is implemented"
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
                "probe_diagnostics": probe_diagnostics,
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
            "probe_diagnostics": probe_diagnostics,
        }
        _write_evidence(marker, result)
        return result
    finally:
        for path in (
            source_canary,
            source_write_target,
            protected_canary,
            outside_canary,
            outside_write_target,
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
