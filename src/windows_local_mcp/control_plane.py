from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from functools import wraps
from pathlib import Path
from typing import Any

from .config import Settings
from .control_plane_guard import assert_control_plane_healthy
from .resources import NamedControlPlaneLock
from .util import canonical_json, sha256_bytes, sha256_text, utc_now_iso

ARCHITECTURE_VERSION = "broker-centered-sandboxed-processing-v1"
POLICY_GENERATION_VERSION = 1
WORKER_CONTEXT_VERSION = 1


def _worker_context_serialized(function: Any) -> Any:
    @wraps(function)
    def locked(settings: Settings, *args: Any, **kwargs: Any) -> Any:
        with NamedControlPlaneLock(settings, "worker-context"):
            return function(settings, *args, **kwargs)

    return locked


def _is_inside(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def _is_reparse(path: Path) -> bool:
    info = path.lstat()
    attributes = int(getattr(info, "st_file_attributes", 0))
    return path.is_symlink() or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def runtime_package_root() -> Path:
    return Path(__file__).resolve(strict=True).parent


def assert_trusted_runtime(settings: Settings) -> Path:
    """Reject a control plane imported from workspace- or data-controlled search paths."""
    package = runtime_package_root()
    protected_roots = [settings.workspace_root.resolve(), settings.data_dir.resolve()]
    if settings.sandbox_scratch_dir is not None:
        protected_roots.append(settings.sandbox_scratch_dir.resolve())
    for protected in protected_roots:
        if _is_inside(package, protected) or _is_inside(protected, package):
            raise RuntimeError(
                "WLMCP runtime must be installed outside workspace_root and data_dir"
            )
    current = package
    while current != Path(current.anchor):
        if _is_reparse(current):
            raise RuntimeError(f"trusted runtime path contains a reparse point: {current}")
        current = current.parent
    executable = Path(sys.executable).resolve(strict=True)
    if any(_is_inside(executable, protected) for protected in protected_roots):
        raise RuntimeError("trusted Python executable is inside an untrusted storage root")
    return package


def _tree_digest(root: Path) -> str:
    records: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.py"), key=lambda item: item.name.casefold()):
        if _is_reparse(path) or not path.is_file():
            raise RuntimeError(f"trusted runtime source is not a regular file: {path}")
        data = path.read_bytes()
        records.append(
            {"path": path.name, "bytes": len(data), "sha256": sha256_bytes(data)}
        )
    if not records:
        raise RuntimeError("trusted runtime package contains no Python source")
    return sha256_text(canonical_json(records))


def filesystem_identity(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    details = resolved.stat()
    return {
        "path": str(resolved),
        "device": int(details.st_dev),
        "inode": int(details.st_ino),
    }


def control_plane_generation(settings: Settings) -> dict[str, Any]:
    assert_control_plane_healthy(settings)
    package = assert_trusted_runtime(settings)
    build = {
        "architecture": ARCHITECTURE_VERSION,
        "runtime_root": str(package),
        "runtime_sha256": _tree_digest(package),
        "python": filesystem_identity(Path(sys.executable)),
    }
    build_digest = sha256_text(canonical_json(build))
    policy = {
        "version": POLICY_GENERATION_VERSION,
        "build_digest": build_digest,
        "settings": settings.model_dump(mode="json"),
        "workspace": filesystem_identity(settings.workspace_root),
        "data_dir": filesystem_identity(settings.data_dir),
        "sandbox_scratch": filesystem_identity(settings.sandbox_scratch_dir)
        if settings.sandbox_scratch_dir is not None
        else None,
    }
    policy_digest = sha256_text(canonical_json(policy))
    return {
        "architecture": ARCHITECTURE_VERSION,
        "build_digest": build_digest,
        "policy_digest": policy_digest,
        "workspace_identity": policy["workspace"],
        "data_dir_identity": policy["data_dir"],
        "sandbox_scratch_identity": policy["sandbox_scratch"],
    }


def verify_control_plane_generation(settings: Settings, expected: object) -> None:
    if not isinstance(expected, dict):
        raise TypeError("operation has no immutable control-plane generation binding")
    current = control_plane_generation(settings)
    if current != expected:
        raise RuntimeError(
            "WLMCP build, security policy, settings, workspace, or data_dir changed "
            "after the operation was created"
        )


@_worker_context_serialized
def create_worker_context(
    settings: Settings, operation_id: str
) -> tuple[Path, str]:
    if not operation_id or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
        for character in operation_id
    ):
        raise ValueError("invalid worker operation id")
    root = settings.data_dir / "worker-contexts"
    root.mkdir(parents=True, exist_ok=True)
    destination = root / f"{operation_id}.json"
    payload = {
        "version": WORKER_CONTEXT_VERSION,
        "operation_id": operation_id,
        "created_at": utc_now_iso(),
        "settings": settings.model_dump(mode="json"),
        "generation": control_plane_generation(settings),
    }
    data = canonical_json(payload).encode("utf-8")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=root) as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
            temporary = Path(output.name)
        os.replace(temporary, destination)
        temporary = None
        destination.chmod(0o444)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination, sha256_bytes(data)


def load_worker_context(
    context_path: str, expected_sha256: str, operation_id: str
) -> Settings:
    path = Path(context_path).resolve(strict=True)
    data = path.read_bytes()
    if sha256_bytes(data) != expected_sha256:
        raise RuntimeError("immutable worker context digest mismatch")
    payload = json.loads(data)
    if (
        payload.get("version") != WORKER_CONTEXT_VERSION
        or payload.get("operation_id") != operation_id
    ):
        raise RuntimeError("immutable worker context identity mismatch")
    settings = Settings.model_validate(payload.get("settings"))
    expected_root = (settings.data_dir / "worker-contexts").resolve(strict=True)
    path.relative_to(expected_root)
    verify_control_plane_generation(settings, payload.get("generation"))
    return settings


def isolated_worker_argv(
    settings: Settings,
    *,
    operation_id: str,
    context_path: Path,
    context_sha256: str,
) -> list[str]:
    package = assert_trusted_runtime(settings)
    source_root = package.parent
    bootstrap = (
        "import runpy,sys;"
        f"sys.path.insert(0,{str(source_root)!r});"
        "runpy.run_module('windows_local_mcp.worker',run_name='__main__')"
    )
    return [
        sys.executable,
        "-I",
        "-c",
        bootstrap,
        "--operation-id",
        operation_id,
        "--context",
        str(context_path),
        "--context-sha256",
        context_sha256,
    ]
