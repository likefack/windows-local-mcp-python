from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from .config import Settings
from .paths import Workspace
from .policy import NormalizedCommand
from .resources import directory_size, enforce_data_quota, scan_directory_bounded
from .safe_process import run_safe_process
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


def prepare_approval_bundle(
    *,
    settings: Settings,
    workspace: Workspace,
    operation_id: str,
    normalized: NormalizedCommand,
    workspace_write: bool = False,
) -> tuple[NormalizedCommand, dict[str, Any], str]:
    """Bind approval to executable bytes and immutable copies of behavior inputs."""
    stage_root = settings.data_dir / "approval-staging" / operation_id
    if stage_root.exists():
        raise RuntimeError("approval staging directory already exists")
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
    }
    execution = normalized.model_copy(deep=True)

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
        manifest_path = stage_root / "manifest.json"
        manifest_path.write_text(canonical_json(manifest), encoding="utf-8")
        _make_read_only(stage_root)
        enforce_data_quota(settings)
        return execution, manifest, digest
    except Exception:
        shutil.rmtree(stage_root, ignore_errors=True)
        raise


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

    executable_record = manifest["executable"]
    if _file_record(
        Path(executable_record["path"]),
        max_bytes=settings.approval_manifest_max_bytes,
        allow_hardlinks=True,
    ) != executable_record:
        raise RuntimeError("approved executable changed after approval was requested")
    for record in manifest.get("inputs", []):
        staged = Path(record["staged_path"])
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
            raise RuntimeError("Git HEAD, index, or working tree changed after approval")
    return NormalizedCommand.model_validate(manifest["execution"])


def materialize_execution_copy(
    *, settings: Settings, operation_id: str, normalized: NormalizedCommand
) -> NormalizedCommand:
    """Create a disposable writable run tree from a verified immutable cwd snapshot."""
    stage_root = (settings.data_dir / "approval-staging" / operation_id).resolve(strict=True)
    immutable_cwd = Path(normalized.cwd).resolve(strict=True)
    expected_cwd = stage_root / "cwd"
    if immutable_cwd != expected_cwd.resolve(strict=True):
        return normalized
    run_root = settings.data_dir / "outputs" / f"{operation_id}-runtime"
    if run_root.exists():
        shutil.rmtree(run_root)
    run_root.mkdir()
    run_cwd = run_root / "cwd"
    shutil.copytree(immutable_cwd, run_cwd, symlinks=False)
    _make_writable(run_cwd)
    immutable_dependencies = stage_root / "dependencies"
    if immutable_dependencies.exists():
        run_dependencies = run_root / "dependencies"
        shutil.copytree(immutable_dependencies, run_dependencies, symlinks=False)
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
    result = normalized.model_copy(deep=True)
    result.args = [
        _rewrite_workspace_argument(value, immutable_cwd, run_cwd)
        for value in result.args
    ]
    result.cwd = str(run_cwd)
    return result


def collect_staged_workspace_write(
    *, settings: Settings, operation_id: str, normalized: NormalizedCommand
) -> dict[str, bytes]:
    """Accept only validated Dart-format target changes from its disposable run tree."""
    stage_root = (settings.data_dir / "approval-staging" / operation_id).resolve(strict=True)
    manifest = json.loads((stage_root / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("mode") != "staged-workspace-write":
        return {}
    if normalized.program_key != "dart" or not normalized.args or normalized.args[0] != "format":
        raise RuntimeError("staged workspace write is not a validated Dart format operation")
    run_cwd = Path(normalized.cwd).resolve(strict=True)
    runtime_root = (settings.data_dir / "outputs" / f"{operation_id}-runtime").resolve(
        strict=True
    )
    run_cwd.relative_to(runtime_root)
    staged_cwd = Path(str(manifest["staged_cwd"])).resolve(strict=True)
    source_cwd = Path(str(manifest["source_cwd"])).resolve(strict=True)
    original = NormalizedCommand.model_validate(manifest["execution"])
    target_values = [value for value in original.args[1:] if not value.startswith("-")]
    allowed_targets: list[Path] = []
    for value in target_values:
        staged_target = Path(value).resolve(strict=True)
        allowed_targets.append(source_cwd / staged_target.relative_to(staged_cwd))
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
        raise RuntimeError("Dart formatter created too many runtime filesystem entries")
    if runtime_scan.total_bytes > settings.approval_manifest_max_bytes:
        raise RuntimeError("Dart formatter outputs exceed approval_manifest_max_bytes")
    actual_files = {path.relative_to(run_cwd).as_posix() for path in runtime_scan.files}
    if actual_files != set(records):
        raise RuntimeError("Dart formatter created or deleted an unapproved file")
    changes: dict[str, bytes] = {}
    changed_bytes = 0
    workspace = Workspace(settings)
    for relative, record in records.items():
        candidate = (run_cwd / Path(relative)).resolve(strict=True)
        candidate.relative_to(run_cwd)
        if candidate.is_symlink() or candidate.stat().st_nlink > 1:
            raise PermissionError("Dart formatter output contains an unsafe file")
        size = candidate.stat().st_size
        if size > settings.max_write_bytes:
            raise ValueError(f"Dart formatter output exceeds max_write_bytes: {relative}")
        changed_bytes += size
        if changed_bytes > settings.approval_manifest_max_bytes:
            raise ValueError("Dart formatter outputs exceed approval_manifest_max_bytes")
        data = candidate.read_bytes()
        if sha256_bytes(data) == record["sha256"] and len(data) == int(record["size"]):
            continue
        source = (source_cwd / Path(relative)).resolve(strict=True)
        if not any(source == target or _is_inside(source, target) for target in allowed_targets):
            raise PermissionError(
                f"Dart formatter changed a file outside validated targets: {relative}"
            )
        workspace_relative = source.relative_to(workspace.root).as_posix()
        workspace.resolve_existing(workspace_relative, allow_directory=False, access="write")
        changes[workspace_relative] = data
    return changes


def _copy_tree_bounded(
    *,
    source: Path,
    destination: Path,
    settings: Settings,
    workspace: Workspace,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    total = 0
    initial_data_bytes = directory_size(
        settings.data_dir, stop_after=settings.max_data_dir_bytes
    )
    for root, directories, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        relative_root = root_path.relative_to(source)
        filtered: list[str] = []
        for name in directories:
            candidate = root_path / name
            if _is_reparse(candidate):
                raise PermissionError(f"approval input contains a reparse point: {candidate}")
            if name.casefold() == ".git":
                continue
            filtered.append(name)
        directories[:] = filtered
        (destination / relative_root).mkdir(parents=True, exist_ok=True)
        for name in files:
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
            shutil.copy2(checked, target)
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
        payload = json.loads(checked_config.read_text(encoding="utf-8"))
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
                )
            else:
                if not any(
                    _is_inside(dependency, allowed)
                    for allowed in settings.safe_network_readable_paths
                ):
                    raise PermissionError(
                        "external Dart package dependency is outside configured "
                        f"safe_network_readable_paths: {dependency}"
                    )
                new_records = _copy_external_tree_bounded(
                    source=dependency,
                    destination=staged_dependency,
                    settings=settings,
                )
            dependency_records.extend(new_records)
            copied[dependency] = staged_dependency
        item["rootUri"] = staged_dependency.as_uri().rstrip("/") + "/"

    staged_config.write_text(canonical_json(payload), encoding="utf-8")
    _refresh_staged_record(records, staged_config)
    return dependency_records


def _copy_external_tree_bounded(
    *, source: Path, destination: Path, settings: Settings
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    total = 0
    initial_data_bytes = directory_size(
        settings.data_dir, stop_after=settings.max_data_dir_bytes
    )
    for root, directories, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        relative_root = root_path.relative_to(source)
        for name in directories:
            candidate = root_path / name
            if _is_reparse(candidate):
                raise PermissionError(f"external dependency contains a reparse point: {candidate}")
        (destination / relative_root).mkdir(parents=True, exist_ok=True)
        for name in files:
            source_file = root_path / name
            if _is_reparse(source_file) or not source_file.is_file():
                raise PermissionError(
                    f"external dependency contains a non-regular file: {source_file}"
                )
            info = source_file.stat()
            if info.st_nlink > 1:
                raise PermissionError(
                    f"external dependency contains a hard-linked file: {source_file}"
                )
            total += info.st_size
            if len(records) + 1 > settings.approval_manifest_max_files:
                raise ValueError("external dependencies exceed approval_manifest_max_files")
            if total > settings.approval_manifest_max_bytes:
                raise ValueError("external dependencies exceed approval_manifest_max_bytes")
            if initial_data_bytes + total > settings.max_data_dir_bytes:
                raise RuntimeError("data_dir quota exceeded while staging dependencies")
            target = destination / relative_root / name
            shutil.copy2(source_file, target)
            record = _file_record(target)
            record.update({"source_path": str(source_file), "staged_path": str(target)})
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
    info = path.stat()
    if not allow_hardlinks and info.st_nlink > 1:
        raise PermissionError(f"approval input with multiple hard links is denied: {path}")
    if max_bytes is not None and info.st_size > max_bytes:
        raise ValueError(f"approval input exceeds byte limit: {path}")
    data = path.read_bytes()
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
    for root, directories, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        directories[:] = [name for name in directories if name.casefold() != ".git"]
        for name in directories:
            if (root_path / name).is_symlink():
                raise PermissionError("workspace inventory contains a reparse point")
        for name in files:
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
            inventory[str(checked)] = (sha256_bytes(checked.read_bytes()), size)
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


def _capture_git_state(
    *, normalized: NormalizedCommand, settings: Settings
) -> dict[str, str]:
    commands = {
        "head": [normalized.executable, "-C", normalized.cwd, "rev-parse", "HEAD"],
        "status": [
            normalized.executable,
            "-C",
            normalized.cwd,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        "diff": [
            normalized.executable,
            "-C",
            normalized.cwd,
            "diff",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
        ],
        "staged": [
            normalized.executable,
            "-C",
            normalized.cwd,
            "diff",
            "--cached",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
        ],
    }
    per_stream = max(4096, settings.approval_manifest_max_bytes // (len(commands) * 2))
    result: dict[str, str] = {}
    for name, command in commands.items():
        captured = run_safe_process(
            settings=settings,
            program_key="git",
            command=command,
            cwd=normalized.cwd,
            timeout=30,
            output_limit=per_stream,
        )
        if captured.returncode != 0:
            raise RuntimeError(
                "Git approval-state capture failed: "
                + captured.stderr.decode("utf-8", errors="replace")[:2000]
            )
        if captured.stdout_truncated or captured.stderr_truncated:
            raise ValueError("Git approval state exceeds approval_manifest_max_bytes")
        result[name] = sha256_bytes(captured.stdout)
    return result
