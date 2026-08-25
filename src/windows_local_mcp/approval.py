from __future__ import annotations

import json
import os
import shutil
import stat
from functools import wraps
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from .config import Settings
from .paths import (
    Workspace,
    hold_verified_path,
    read_verified_bytes,
    release_verified_hold,
)
from .policy import NormalizedCommand
from .resources import (
    NamedControlPlaneLock,
    directory_size,
    enforce_data_quota,
    scan_directory_bounded,
)
from .util import canonical_json, sha256_bytes, sha256_text

_CODE_LOADERS = {
    "python",
    "python3",
    "py",
    "pytest",
    "node",
    "npm",
    "npx",
    "dart",
    "flutter",
    "powershell",
    "pwsh",
    "cmd",
    "bash",
    "sh",
}


class _EntryBudget:
    """Bound every traversed filesystem entry across one approval staging operation."""

    def __init__(self, settings: Settings) -> None:
        self.limit = max(128, settings.approval_manifest_max_files * 4)
        self.count = 0

    def consume(self) -> None:
        self.count += 1
        if self.count > self.limit:
            raise ValueError("approval staging filesystem entry count exceeds limit")


def _sandbox_scratch_entry_limit(settings: Settings) -> int:
    # Charge at least one 4 KiB allocation unit per directory/file entry so empty directory
    # trees cannot bypass the byte-oriented scratch quota through filesystem metadata alone.
    return max(1024, settings.max_sandbox_scratch_bytes // 4096)


def _enforce_sandbox_scratch_quota(
    settings: Settings, *, admission: bool = False
) -> None:
    assert settings.sandbox_scratch_dir is not None
    entry_limit = _sandbox_scratch_entry_limit(settings)
    usage = scan_directory_bounded(
        settings.sandbox_scratch_dir,
        stop_after_bytes=settings.max_sandbox_scratch_bytes,
        stop_after_entries=entry_limit,
        reject_alternate_streams=True,
        reject_reparse_points=True,
    )
    if admission:
        exceeded = (
            usage.total_bytes >= settings.max_sandbox_scratch_bytes
            or usage.entry_count >= entry_limit
        )
        message = "sandbox scratch admission limit reached"
    else:
        exceeded = (
            usage.total_bytes > settings.max_sandbox_scratch_bytes
            or usage.entry_count > entry_limit
        )
        message = "approval staging exceeds sandbox scratch resource limits"
    if exceeded:
        raise RuntimeError(message)


def _approval_staging_serialized(function: Any) -> Any:
    @wraps(function)
    def locked(*args: Any, **kwargs: Any) -> Any:
        settings = kwargs.get("settings") or (args[0] if args else None)
        if not isinstance(settings, Settings):
            raise TypeError("approval staging operation has no Settings binding")
        with NamedControlPlaneLock(settings, "approval-staging"):
            return function(*args, **kwargs)

    return locked


@_approval_staging_serialized
def prepare_approval_bundle(
    *,
    settings: Settings,
    workspace: Workspace,
    operation_id: str,
    normalized: NormalizedCommand,
    workspace_write: bool = False,
) -> tuple[NormalizedCommand, dict[str, Any], str]:
    """Bind approval to executable bytes and immutable copies of behavior inputs."""
    manifest_root = settings.data_dir / "approval-staging" / operation_id
    assert settings.sandbox_scratch_dir is not None
    _enforce_sandbox_scratch_quota(settings, admission=True)
    stage_root = settings.sandbox_scratch_dir / "approval-inputs" / operation_id
    if manifest_root.exists() or stage_root.exists():
        raise RuntimeError("approval staging directory already exists")
    manifest_root.mkdir(parents=True)
    stage_root.mkdir(parents=True)

    executable = Path(normalized.executable)
    executable_record = _file_record(
        executable,
        max_bytes=settings.approval_manifest_max_bytes,
        allow_hardlinks=True,
    )
    manifest: dict[str, Any] = {
        "version": 1,
        "operation_id": operation_id,
        "executable": executable_record,
        "settings_digest": settings_digest(settings),
        "environment_digest": _environment_digest(),
        "mode": "source-workspace",
        "inputs": [],
        "execution_staging_root": str(stage_root),
    }
    execution = normalized.model_copy(deep=True)
    entry_budget = _EntryBudget(settings)

    try:
        manifest["external_inputs"] = _validate_external_arguments(
            normalized.args,
            cwd=Path(normalized.cwd),
            workspace=workspace,
            code_loader=normalized.program_key in _CODE_LOADERS,
        )
        manifest["workspace_write"] = workspace_write

        if normalized.program_key in _CODE_LOADERS:
            source_cwd = Path(normalized.cwd)
            staged_cwd = stage_root / "cwd"
            records = _copy_tree_bounded(
                source=source_cwd,
                destination=staged_cwd,
                settings=settings,
                workspace=workspace,
                entry_budget=entry_budget,
            )
            manifest["mode"] = (
                "staged-workspace-write" if workspace_write else "staged-cwd"
            )
            manifest["source_cwd"] = normalized.cwd
            manifest["staged_cwd"] = str(staged_cwd)
            manifest["inputs"] = records
            execution.cwd = str(staged_cwd)
            execution.args = [
                _rewrite_workspace_argument(value, Path(normalized.cwd), staged_cwd)
                for value in execution.args
            ]
            if normalized.program_key in {"dart", "flutter"}:
                dependency_records = _stage_dart_package_dependencies(
                    source_cwd=source_cwd,
                    staged_cwd=staged_cwd,
                    stage_root=stage_root,
                    settings=settings,
                    workspace=workspace,
                    records=records,
                    entry_budget=entry_budget,
                )
                records.extend(dependency_records)
                manifest["inputs"] = records
            _enforce_manifest_totals(records, settings)
            root_text = str(workspace.root).casefold()
            if any(root_text in value.casefold() for value in execution.args):
                raise PermissionError(
                    "embedded workspace paths cannot be safely rewritten for immutable execution"
                )
        else:
            staged_workspace = stage_root / "workspace"
            records = _copy_tree_bounded(
                source=workspace.root,
                destination=staged_workspace,
                settings=settings,
                workspace=workspace,
                entry_budget=entry_budget,
            )
            manifest["inputs"] = records
            manifest["source_workspace"] = str(workspace.root)
            manifest["staged_workspace"] = str(staged_workspace)
            if normalized.program_key == "git":
                manifest["mode"] = "git-state-source-workspace"
                manifest["git_state"] = _capture_git_state(
                    normalized=normalized,
                    settings=settings,
                )
        manifest["execution"] = execution.model_dump()
        digest = sha256_text(canonical_json(manifest))
        manifest["digest"] = digest
        manifest_path = manifest_root / "manifest.json"
        manifest_path.write_text(canonical_json(manifest), encoding="utf-8")
        _make_read_only(stage_root)
        _make_read_only(manifest_root)
        enforce_data_quota(settings)
        _enforce_sandbox_scratch_quota(settings)
        return execution, manifest, digest
    except Exception:
        shutil.rmtree(stage_root, ignore_errors=True)
        shutil.rmtree(manifest_root, ignore_errors=True)
        raise


@_approval_staging_serialized
def verify_approval_bundle(
    *, settings: Settings, operation_id: str, expected_digest: str
) -> NormalizedCommand:
    stage_root = (settings.data_dir / "approval-staging" / operation_id).resolve(strict=True)
    allowed_root = (settings.data_dir / "approval-staging").resolve(strict=True)
    try:
        stage_root.relative_to(allowed_root)
    except ValueError as error:
        raise PermissionError("approval manifest escapes the staging directory") from error
    if stage_root.is_symlink():
        raise PermissionError("approval staging directory must not be a reparse point")
    manifest_path = stage_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    stored_digest = manifest.pop("digest", None)
    actual_digest = sha256_text(canonical_json(manifest))
    if stored_digest != expected_digest or actual_digest != expected_digest:
        raise RuntimeError("approval manifest digest mismatch")
    if manifest.get("settings_digest") != settings_digest(settings):
        raise RuntimeError("effective MCP settings changed after approval was requested")
    if manifest.get("environment_digest") != _environment_digest():
        raise RuntimeError("command-affecting environment changed after approval was requested")
    assert settings.sandbox_scratch_dir is not None
    expected_execution_root = (
        settings.sandbox_scratch_dir / "approval-inputs" / operation_id
    ).resolve(strict=True)
    if Path(str(manifest.get("execution_staging_root"))).resolve(strict=True) != expected_execution_root:
        raise RuntimeError("approval execution staging root changed after request creation")

    executable_record = manifest["executable"]
    if _file_record(
        Path(executable_record["path"]),
        max_bytes=settings.approval_manifest_max_bytes,
        allow_hardlinks=True,
    ) != executable_record:
        raise RuntimeError("approved executable changed after approval was requested")
    for record in manifest.get("inputs", []):
        staged = Path(record["staged_path"])
        staged.resolve(strict=True).relative_to(expected_execution_root)
        current = _file_record(staged)
        if current["sha256"] != record["sha256"] or current["size"] != record["size"]:
            raise RuntimeError("approved input changed after approval was requested")
    if manifest.get("mode") == "staged-workspace-write":
        for record in manifest.get("inputs", []):
            source_value = record.get("source_path")
            if not source_value:
                continue
            source = Path(str(source_value))
            try:
                source.relative_to(settings.workspace_root)
            except ValueError:
                continue
            current = _file_record(
                source, max_bytes=settings.approval_manifest_max_bytes
            )
            if current["sha256"] != record["sha256"] or current["size"] != record["size"]:
                raise RuntimeError("workspace files changed after formatting was staged")
    for record in manifest.get("external_inputs", []):
        current = _file_record(Path(record["path"]), max_bytes=settings.approval_manifest_max_bytes)
        if current != record:
            raise RuntimeError("external approved input changed after approval was requested")
    if manifest.get("mode") in {"source-workspace", "git-state-source-workspace"}:
        expected_sources = {
            record["source_path"]: (record["sha256"], record["size"])
            for record in manifest.get("inputs", [])
        }
        actual_sources = _source_inventory(
            source=Path(manifest["source_workspace"]),
            settings=settings,
            workspace=Workspace(settings),
        )
        if actual_sources != expected_sources:
            raise RuntimeError("workspace files changed after approval was requested")
    if manifest.get("mode") == "git-state-source-workspace":
        current_state = _capture_git_state(
            normalized=NormalizedCommand.model_validate(manifest["execution"]),
            settings=settings,
        )
        if current_state != manifest.get("git_state"):
            raise RuntimeError("Git metadata changed after approval")
    return NormalizedCommand.model_validate(manifest["execution"])


@_approval_staging_serialized
def materialize_execution_copy(
    *, settings: Settings, operation_id: str, normalized: NormalizedCommand
) -> NormalizedCommand:
    """Create a disposable writable run tree from a verified immutable cwd snapshot."""
    manifest_root = (settings.data_dir / "approval-staging" / operation_id).resolve(strict=True)
    manifest = json.loads((manifest_root / "manifest.json").read_text(encoding="utf-8"))
    stage_root = Path(str(manifest["execution_staging_root"])).resolve(strict=True)
    assert settings.sandbox_scratch_dir is not None
    stage_root.relative_to((settings.sandbox_scratch_dir / "approval-inputs").resolve(strict=True))
    immutable_cwd = Path(normalized.cwd).resolve(strict=True)
    expected_cwd = Path(str(manifest.get("staged_cwd", stage_root / "cwd")))
    if immutable_cwd != expected_cwd.resolve(strict=True):
        return normalized
    _enforce_sandbox_scratch_quota(settings, admission=True)
    run_root = settings.sandbox_scratch_dir / "runs" / operation_id
    if run_root.exists():
        shutil.rmtree(run_root)
    run_root.mkdir(parents=True)
    run_cwd = run_root / "cwd"
    entry_budget = _EntryBudget(settings)
    try:
        _copy_external_tree_bounded(
            source=immutable_cwd,
            destination=run_cwd,
            settings=settings,
            entry_budget=entry_budget,
            charge_data_dir=False,
        )
        _make_writable(run_cwd)
        immutable_dependencies = stage_root / "dependencies"
        if immutable_dependencies.exists():
            run_dependencies = run_root / "dependencies"
            _copy_external_tree_bounded(
                source=immutable_dependencies,
                destination=run_dependencies,
                settings=settings,
                entry_budget=entry_budget,
                charge_data_dir=False,
            )
            package_config = run_cwd / ".dart_tool" / "package_config.json"
            if package_config.exists():
                payload = json.loads(package_config.read_text(encoding="utf-8"))
                for item in payload.get("packages", []):
                    root_uri = str(item.get("rootUri", ""))
                    parsed = urlparse(root_uri)
                    if parsed.scheme != "file":
                        continue
                    staged_dependency = Path(unquote(parsed.path.lstrip("/")))
                    if os.name == "nt" and parsed.path.startswith("/"):
                        staged_dependency = Path(unquote(parsed.path[1:]))
                    staged_dependency = staged_dependency.resolve(strict=True)
                    try:
                        relative_dependency = staged_dependency.relative_to(
                            immutable_dependencies.resolve(strict=True)
                        )
                    except ValueError:
                        continue
                    item["rootUri"] = (
                        (run_dependencies / relative_dependency).as_uri().rstrip("/") + "/"
                    )
                package_config.write_text(canonical_json(payload), encoding="utf-8")
        _enforce_sandbox_scratch_quota(settings)
    except Exception:
        shutil.rmtree(run_root, ignore_errors=True)
        raise
    result = normalized.model_copy(deep=True)
    result.args = [
        _rewrite_workspace_argument(value, immutable_cwd, run_cwd)
        for value in result.args
    ]
    result.cwd = str(run_cwd)
    return result


def collect_staged_workspace_changes(
    *, settings: Settings, operation_id: str, normalized: NormalizedCommand
) -> tuple[dict[str, bytes], set[str]]:
    """Validate a disposable run tree and return its closed-world workspace delta."""
    stage_root = (settings.data_dir / "approval-staging" / operation_id).resolve(strict=True)
    manifest = json.loads((stage_root / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("mode") != "staged-workspace-write":
        return {}, set()
    run_cwd = Path(normalized.cwd).resolve(strict=True)
    assert settings.sandbox_scratch_dir is not None
    runtime_root = (settings.sandbox_scratch_dir / "runs" / operation_id).resolve(strict=True)
    run_cwd.relative_to(runtime_root)
    staged_cwd = Path(str(manifest["staged_cwd"])).resolve(strict=True)
    source_cwd = Path(str(manifest["source_cwd"])).resolve(strict=True)
    records: dict[str, dict[str, Any]] = {}
    for record in manifest.get("inputs", []):
        staged_path = Path(str(record["staged_path"])).resolve(strict=True)
        try:
            relative = staged_path.relative_to(staged_cwd).as_posix()
        except ValueError:
            continue
        records[relative] = record
    runtime_entry_limit = max(128, settings.approval_manifest_max_files * 4)
    runtime_scan = scan_directory_bounded(
        run_cwd,
        stop_after_bytes=settings.approval_manifest_max_bytes,
        stop_after_entries=runtime_entry_limit,
        collect_files=True,
        reject_alternate_streams=True,
        reject_reparse_points=True,
    )
    if runtime_scan.entry_count > runtime_entry_limit:
        raise RuntimeError("sandbox processing created too many runtime filesystem entries")
    if runtime_scan.total_bytes > settings.approval_manifest_max_bytes:
        raise RuntimeError("sandbox outputs exceed approval_manifest_max_bytes")
    actual_files = {path.relative_to(run_cwd).as_posix() for path in runtime_scan.files}
    changes: dict[str, bytes] = {}
    deletions: set[str] = set()
    changed_bytes = 0
    workspace = Workspace(settings)
    for relative in sorted(actual_files):
        candidate = (run_cwd / Path(relative)).resolve(strict=True)
        candidate.relative_to(run_cwd)
        if candidate.is_symlink() or candidate.stat().st_nlink > 1:
            raise PermissionError("sandbox output contains an unsafe file")
        size = candidate.stat().st_size
        if size > settings.max_write_bytes:
            raise ValueError(f"sandbox output exceeds max_write_bytes: {relative}")
        changed_bytes += size
        if changed_bytes > settings.approval_manifest_max_bytes:
            raise ValueError("sandbox outputs exceed approval_manifest_max_bytes")
        data = candidate.read_bytes()
        record = records.get(relative)
        if record is not None and sha256_bytes(data) == record["sha256"] and len(data) == int(record["size"]):
            continue
        source = source_cwd / Path(relative)
        workspace_relative = source.relative_to(workspace.root).as_posix()
        workspace.resolve_planned_write(workspace_relative)
        changes[workspace_relative] = data
    for relative in sorted(set(records) - actual_files):
        source = source_cwd / Path(relative)
        workspace_relative = source.relative_to(workspace.root).as_posix()
        workspace.resolve_existing(workspace_relative, allow_directory=False, access="write")
        deletions.add(workspace_relative)
    return changes, deletions


def _copy_tree_bounded(
    *,
    source: Path,
    destination: Path,
    settings: Settings,
    workspace: Workspace,
    entry_budget: _EntryBudget | None = None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    total = 0
    budget = entry_budget or _EntryBudget(settings)
    initial_data_bytes = directory_size(
        settings.data_dir, stop_after=settings.max_data_dir_bytes
    )
    blocked_files = {name.casefold() for name in settings.blocked_file_names}
    excluded_directories = {
        name.casefold()
        for name in settings.hidden_directories
        if name.casefold() != ".dart_tool"
    }
    for root, directories, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        relative_root = root_path.relative_to(source)
        filtered: list[str] = []
        for name in directories:
            budget.consume()
            candidate = root_path / name
            if _is_reparse(candidate):
                raise PermissionError(f"approval input contains a reparse point: {candidate}")
            if name.casefold() == ".git" or name.casefold() in excluded_directories:
                continue
            filtered.append(name)
        directories[:] = filtered
        (destination / relative_root).mkdir(parents=True, exist_ok=True)
        for name in files:
            budget.consume()
            folded = name.casefold()
            if folded in blocked_files or (
                folded.startswith(".env.") and folded != ".env.example"
            ):
                continue
            source_file = root_path / name
            relative_workspace = source_file.relative_to(workspace.root)
            checked = workspace.resolve_existing(
                str(relative_workspace), allow_directory=False, access="read"
            )
            size = checked.stat().st_size
            total += size
            if len(records) + 1 > settings.approval_manifest_max_files:
                raise ValueError("approval input count exceeds approval_manifest_max_files")
            if total > settings.approval_manifest_max_bytes:
                raise ValueError("approval inputs exceed approval_manifest_max_bytes")
            if initial_data_bytes + total > settings.max_data_dir_bytes:
                raise RuntimeError("data_dir quota exceeded while staging approval inputs")
            target = destination / relative_root / name
            target.write_bytes(
                read_verified_bytes(checked, settings.approval_manifest_max_bytes)
            )
            shutil.copystat(checked, target, follow_symlinks=False)
            record = _file_record(target)
            record.update({"source_path": str(checked), "staged_path": str(target)})
            records.append(record)
    return records


def _stage_dart_package_dependencies(
    *,
    source_cwd: Path,
    staged_cwd: Path,
    stage_root: Path,
    settings: Settings,
    workspace: Workspace,
    records: list[dict[str, Any]],
    entry_budget: _EntryBudget,
) -> list[dict[str, Any]]:
    source_config = source_cwd / ".dart_tool" / "package_config.json"
    if not source_config.exists():
        return []
    checked_config = workspace.resolve_existing(
        str(source_config.relative_to(workspace.root)),
        allow_directory=False,
        access="read",
    )
    try:
        config_bytes = read_verified_bytes(
            checked_config, settings.approval_manifest_max_bytes
        )
        payload = json.loads(config_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid Dart package_config.json") from error
    packages = payload.get("packages")
    if not isinstance(packages, list):
        raise TypeError("Dart package_config.json has no packages array")

    staged_config = staged_cwd / ".dart_tool" / "package_config.json"
    dependency_root = stage_root / "dependencies"
    copied: dict[Path, Path] = {}
    dependency_records: list[dict[str, Any]] = []
    for index, item in enumerate(packages):
        if not isinstance(item, dict) or not isinstance(item.get("rootUri"), str):
            raise TypeError("Dart package_config.json contains an invalid package entry")
        root_uri = item["rootUri"]
        parsed = urlparse(root_uri)
        if parsed.scheme not in {"", "file"}:
            raise PermissionError(f"non-file Dart package dependency is denied: {root_uri}")
        if parsed.scheme == "file":
            dependency = Path(unquote(parsed.path.lstrip("/")))
            if os.name == "nt" and parsed.path.startswith("/"):
                dependency = Path(unquote(parsed.path[1:]))
        else:
            dependency = checked_config.parent / unquote(parsed.path)
        dependency = dependency.resolve(strict=True)
        if not dependency.is_dir() or _is_reparse(dependency):
            raise PermissionError(f"Dart package dependency is not a stable directory: {dependency}")
        try:
            dependency.relative_to(source_cwd)
            continue
        except ValueError:
            pass
        staged_dependency = copied.get(dependency)
        if staged_dependency is None:
            package_name = str(item.get("name", f"package-{index}"))
            safe_name = "".join(
                character if character.isalnum() or character in {"-", "_"} else "_"
                for character in package_name
            )
            staged_dependency = dependency_root / f"{index:04d}-{safe_name}"
            if _is_inside(dependency, workspace.root):
                new_records = _copy_tree_bounded(
                    source=dependency,
                    destination=staged_dependency,
                    settings=settings,
                    workspace=workspace,
                    entry_budget=entry_budget,
                )
            else:
                if not any(
                    _is_inside(dependency, allowed)
                    for allowed in settings.sandbox_dependency_readable_paths
                ):
                    raise PermissionError(
                        "external Dart package dependency is outside configured "
                        f"sandbox_dependency_readable_paths: {dependency}"
                    )
                new_records = _copy_external_tree_bounded(
                    source=dependency,
                    destination=staged_dependency,
                    settings=settings,
                    entry_budget=entry_budget,
                )
            dependency_records.extend(new_records)
            copied[dependency] = staged_dependency
        item["rootUri"] = staged_dependency.as_uri().rstrip("/") + "/"

    staged_config.write_text(canonical_json(payload), encoding="utf-8")
    _refresh_staged_record(records, staged_config)
    return dependency_records


def _copy_external_tree_bounded(
    *,
    source: Path,
    destination: Path,
    settings: Settings,
    entry_budget: _EntryBudget | None = None,
    charge_data_dir: bool = True,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    total = 0
    budget = entry_budget or _EntryBudget(settings)
    initial_data_bytes = (
        directory_size(settings.data_dir, stop_after=settings.max_data_dir_bytes)
        if charge_data_dir
        else 0
    )
    for root, directories, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        relative_root = root_path.relative_to(source)
        for name in directories:
            budget.consume()
            candidate = root_path / name
            if _is_reparse(candidate):
                raise PermissionError(f"external dependency contains a reparse point: {candidate}")
        (destination / relative_root).mkdir(parents=True, exist_ok=True)
        for name in files:
            budget.consume()
            source_file = root_path / name
            if _is_reparse(source_file) or not source_file.is_file():
                raise PermissionError(
                    f"external dependency contains a non-regular file: {source_file}"
                )
            checked = hold_verified_path(
                source_file, allow_directory=False, readable=True
            )
            info = checked.stat()
            if info.st_nlink > 1:
                raise PermissionError(
                    f"external dependency contains a hard-linked file: {checked}"
                )
            total += info.st_size
            if len(records) + 1 > settings.approval_manifest_max_files:
                raise ValueError("external dependencies exceed approval_manifest_max_files")
            if total > settings.approval_manifest_max_bytes:
                raise ValueError("external dependencies exceed approval_manifest_max_bytes")
            if charge_data_dir and initial_data_bytes + total > settings.max_data_dir_bytes:
                raise RuntimeError("data_dir quota exceeded while staging dependencies")
            target = destination / relative_root / name
            target.write_bytes(
                read_verified_bytes(checked, settings.approval_manifest_max_bytes)
            )
            shutil.copystat(checked, target, follow_symlinks=False)
            record = _file_record(target)
            record.update({"source_path": str(checked), "staged_path": str(target)})
            records.append(record)
    return records


def _refresh_staged_record(records: list[dict[str, Any]], staged: Path) -> None:
    for record in records:
        if Path(record["staged_path"]) == staged:
            refreshed = _file_record(staged)
            record.update(
                {
                    "path": refreshed["path"],
                    "size": refreshed["size"],
                    "sha256": refreshed["sha256"],
                    "device": refreshed["device"],
                    "inode": refreshed["inode"],
                    "modified_ns": refreshed["modified_ns"],
                }
            )
            return
    raise RuntimeError("staged package_config.json was not present in the manifest")


def _enforce_manifest_totals(records: list[dict[str, Any]], settings: Settings) -> None:
    if len(records) > settings.approval_manifest_max_files:
        raise ValueError("approval inputs exceed approval_manifest_max_files")
    if sum(int(record["size"]) for record in records) > settings.approval_manifest_max_bytes:
        raise ValueError("approval inputs exceed approval_manifest_max_bytes")


def _is_reparse(path: Path) -> bool:
    info = path.lstat()
    attributes = int(getattr(info, "st_file_attributes", 0))
    return path.is_symlink() or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _is_inside(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def _file_record(
    path: Path,
    *,
    max_bytes: int | None = None,
    allow_hardlinks: bool = False,
) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PermissionError(f"approval input must be a regular non-reparse file: {path}")
    path = hold_verified_path(
        path,
        allow_directory=False,
        allow_hardlinks=allow_hardlinks,
        readable=True,
    )
    info = path.stat()
    if not allow_hardlinks and info.st_nlink > 1:
        raise PermissionError(f"approval input with multiple hard links is denied: {path}")
    if max_bytes is not None and info.st_size > max_bytes:
        raise ValueError(f"approval input exceeds byte limit: {path}")
    data = read_verified_bytes(
        path, max_bytes if max_bytes is not None else info.st_size
    )
    return {
        "path": str(path.resolve()),
        "size": len(data),
        "sha256": sha256_bytes(data),
        "device": info.st_dev,
        "inode": info.st_ino,
        "modified_ns": info.st_mtime_ns,
    }


def _rewrite_workspace_argument(value: str, source_cwd: Path, staged_cwd: Path) -> str:
    prefix, candidate_text = _split_option_path(value)
    candidate = Path(candidate_text)
    if not candidate.is_absolute():
        candidate = source_cwd / candidate
    try:
        relative = candidate.resolve(strict=True).relative_to(source_cwd)
    except (FileNotFoundError, ValueError, OSError):
        return value
    return prefix + str(staged_cwd / relative)


def _split_option_path(value: str) -> tuple[str, str]:
    if value.startswith("-") and "=" in value:
        option, candidate = value.split("=", 1)
        return option + "=", candidate
    return "", value


def _validate_external_arguments(
    args: list[str],
    *,
    cwd: Path,
    workspace: Workspace,
    code_loader: bool,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for value in args:
        _, candidate_text = _split_option_path(value)
        has_embedded_absolute = bool(
            len(candidate_text) >= 3
            and candidate_text[0].isalpha()
            and candidate_text[1] == ":"
            and candidate_text[2] in {"\\", "/"}
        ) or candidate_text.startswith(("\\\\", "//"))
        candidate = Path(candidate_text)
        if not candidate.is_absolute():
            candidate = cwd / candidate
        try:
            resolved = candidate.resolve(strict=True)
        except (FileNotFoundError, OSError):
            if code_loader and has_embedded_absolute:
                raise PermissionError(
                    "code-loader arguments may not contain unbound absolute paths"
                ) from None
            continue
        try:
            resolved.relative_to(workspace.root)
            continue
        except ValueError:
            pass
        if code_loader:
            raise PermissionError(
                f"code-loader input outside workspace cannot be completely enumerated: {resolved}"
            )
        if not resolved.is_file():
            raise PermissionError(
                f"external directory input cannot be completely enumerated: {resolved}"
            )
        records.append(_file_record(resolved))
    return records


def _source_inventory(
    *, source: Path, settings: Settings, workspace: Workspace
) -> dict[str, tuple[str, int]]:
    inventory: dict[str, tuple[str, int]] = {}
    total = 0
    count = 0
    entry_budget = _EntryBudget(settings)
    excluded_directories = {
        name.casefold()
        for name in settings.hidden_directories
        if name.casefold() != ".dart_tool"
    }
    blocked_files = {name.casefold() for name in settings.blocked_file_names}
    for root, directories, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        for _name in directories:
            entry_budget.consume()
        directories[:] = [
            name
            for name in directories
            if name.casefold() != ".git" and name.casefold() not in excluded_directories
        ]
        for name in directories:
            if (root_path / name).is_symlink():
                raise PermissionError("workspace inventory contains a reparse point")
        for name in files:
            entry_budget.consume()
            folded = name.casefold()
            if folded in blocked_files or (
                folded.startswith(".env.") and folded != ".env.example"
            ):
                continue
            source_file = root_path / name
            relative_workspace = source_file.relative_to(workspace.root)
            checked = workspace.resolve_existing(
                str(relative_workspace), allow_directory=False, access="read"
            )
            size = checked.stat().st_size
            total += size
            count += 1
            if count > settings.approval_manifest_max_files:
                raise ValueError("workspace inventory exceeds approval_manifest_max_files")
            if total > settings.approval_manifest_max_bytes:
                raise ValueError("workspace inventory exceeds approval_manifest_max_bytes")
            inventory[str(checked)] = (
                sha256_bytes(
                    read_verified_bytes(checked, settings.approval_manifest_max_bytes)
                ),
                size,
            )
    return inventory


def settings_digest(settings: Settings) -> str:
    return sha256_text(canonical_json(settings.model_dump(mode="json")))


def _environment_digest() -> str:
    relevant = {
        key: value
        for key, value in os.environ.items()
        if key.casefold()
        in {
            "path",
            "pathext",
            "systemroot",
            "comspec",
            "temp",
            "tmp",
            "userprofile",
            "home",
            "appdata",
            "localappdata",
            "pub_cache",
            "flutter_root",
            "android_home",
            "android_sdk_root",
            "java_home",
            "local_mcp_config",
            "local_mcp_root",
            "local_mcp_transport",
        }
    }
    return sha256_text(canonical_json(relevant))


def _make_read_only(root: Path) -> None:
    for current, directories, files in os.walk(root):
        for name in files:
            (Path(current) / name).chmod(0o444)
        for name in directories:
            (Path(current) / name).chmod(0o555)
    root.chmod(0o555)


def _make_writable(root: Path) -> None:
    root.chmod(0o755)
    for current, directories, files in os.walk(root):
        for name in directories:
            (Path(current) / name).chmod(0o755)
        for name in files:
            (Path(current) / name).chmod(0o644)


def _git_metadata_root(
    *, normalized: NormalizedCommand, settings: Settings
) -> Path:
    workspace_root = settings.workspace_root.resolve(strict=True)
    current = Path(normalized.cwd).resolve(strict=True)
    try:
        current.relative_to(workspace_root)
    except ValueError as error:
        raise PermissionError("Git approval cwd escapes workspace_root") from error

    while True:
        marker = current / ".git"
        if os.path.lexists(marker):
            if _is_reparse(marker) or not marker.is_dir():
                raise PermissionError(
                    "Git approval requires repository metadata to be an in-workspace .git directory; "
                    "gitfiles and reparse points are denied"
                )
            held = hold_verified_path(
                marker,
                allow_directory=True,
                allow_hardlinks=True,
            )
            try:
                Path(str(held)).relative_to(workspace_root)
            except ValueError:
                release_verified_hold(held)
                raise PermissionError("Git repository metadata escapes workspace_root") from None
            return held
        if current == workspace_root:
            break
        current = current.parent
    raise PermissionError("Git approval requires repository metadata inside workspace_root")


def _git_metadata_inventory_once(
    metadata_root: Path, settings: Settings
) -> dict[str, tuple[str, int]]:
    inventory: dict[str, tuple[str, int]] = {}
    total = 0
    count = 0
    entry_budget = _EntryBudget(settings)
    for root, directories, files in os.walk(metadata_root, followlinks=False):
        root_path = Path(root)
        for name in directories:
            entry_budget.consume()
            candidate = root_path / name
            if _is_reparse(candidate):
                raise PermissionError(
                    f"Git repository metadata contains a reparse point: {candidate}"
                )
        for name in files:
            entry_budget.consume()
            source_file = root_path / name
            if _is_reparse(source_file) or not source_file.is_file():
                raise PermissionError(
                    f"Git repository metadata contains a non-regular file: {source_file}"
                )
            checked = hold_verified_path(
                source_file,
                allow_directory=False,
                allow_hardlinks=False,
                readable=True,
            )
            try:
                info = checked.stat()
                total += info.st_size
                count += 1
                if count > settings.approval_manifest_max_files:
                    raise ValueError(
                        "Git repository metadata exceeds approval_manifest_max_files"
                    )
                if total > settings.approval_manifest_max_bytes:
                    raise ValueError(
                        "Git repository metadata exceeds approval_manifest_max_bytes"
                    )
                data = read_verified_bytes(
                    checked, settings.approval_manifest_max_bytes
                )
                relative = Path(str(checked)).relative_to(metadata_root).as_posix()
                inventory[relative] = (sha256_bytes(data), len(data))
            finally:
                release_verified_hold(checked)
    return inventory


def _capture_git_state(
    *, normalized: NormalizedCommand, settings: Settings
) -> dict[str, str]:
    """Bind Git metadata without executing Git or following repository indirections."""
    metadata_root = _git_metadata_root(normalized=normalized, settings=settings)
    try:
        first = _git_metadata_inventory_once(metadata_root, settings)
        second = _git_metadata_inventory_once(metadata_root, settings)
        if first != second:
            raise RuntimeError("Git repository metadata changed while approval state was captured")
        return {
            "metadata_root": Path(str(metadata_root))
            .relative_to(settings.workspace_root.resolve(strict=True))
            .as_posix(),
            "metadata_digest": sha256_text(canonical_json(first)),
        }
    finally:
        release_verified_hold(metadata_root)
