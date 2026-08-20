from __future__ import annotations

import os
from pathlib import Path

import pytest

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.executor import Executor
from windows_local_mcp.runtime_immutability import (
    _MUTATING_ACCESS_MASK,
    _runtime_paths,
    assert_approved_host_runtime_immutable,
    windows_effective_runtime_access,
)
from windows_local_mcp.runtime_trust import RuntimeTree, RuntimeTrustInventory


def _inventory(tmp_path: Path) -> tuple[RuntimeTrustInventory, dict[str, Path]]:
    repository = tmp_path / "repo"
    source_root = repository / "src"
    package = source_root / "windows_local_mcp"
    package.mkdir(parents=True)
    (repository / "pyproject.toml").write_text("[project]\nname='test'\n", encoding="utf-8")
    (repository / "run-server.ps1").write_text("Write-Output test\n", encoding="utf-8")
    (repository / "run-approvals.ps1").write_text("Write-Output test\n", encoding="utf-8")
    package_file = package / "__init__.py"
    package_file.write_text("VALUE = 1\n", encoding="utf-8")

    site_root = tmp_path / "venv" / "Lib" / "site-packages"
    dependency = site_root / "pydantic"
    dependency.mkdir(parents=True)
    dependency_file = dependency / "__init__.py"
    dependency_file.write_text("VALUE = 1\n", encoding="utf-8")
    startup = site_root / "runtime-hook.pth"
    startup.write_text("# startup\n", encoding="utf-8")
    optional = site_root / "optional_plugin" / "__init__.py"
    optional.parent.mkdir()
    optional.write_text("VALUE = 1\n", encoding="utf-8")

    inventory = RuntimeTrustInventory(
        trees=(RuntimeTree(package), RuntimeTree(dependency)),
        namespace_roots=(source_root, site_root),
        security_paths=(source_root, site_root),
        files=(startup,),
        distributions=(("pydantic", "2.test"),),
    )
    return inventory, {
        "repository": repository,
        "source_root": source_root,
        "package": package,
        "package_file": package_file,
        "site_root": site_root,
        "dependency_file": dependency_file,
        "startup": startup,
        "optional": optional,
    }


def test_complete_runtime_rejects_mutating_access_on_dependency_file(tmp_path: Path) -> None:
    inventory, paths = _inventory(tmp_path)

    def access(path: Path) -> int:
        if path == paths["dependency_file"].resolve(strict=True):
            return 0x00000002  # FILE_WRITE_DATA
        return 0

    with pytest.raises(PermissionError, match="immutable Python/WLMCP runtime"):
        assert_approved_host_runtime_immutable(
            paths["package"],
            inventory=inventory,
            access_resolver=access,
        )


def test_complete_runtime_rejects_mutating_startup_pth(tmp_path: Path) -> None:
    inventory, paths = _inventory(tmp_path)

    def access(path: Path) -> int:
        if path == paths["startup"].resolve(strict=True):
            return 0x00000002  # FILE_WRITE_DATA
        return 0

    with pytest.raises(PermissionError, match="immutable Python/WLMCP runtime"):
        assert_approved_host_runtime_immutable(
            paths["package"],
            inventory=inventory,
            access_resolver=access,
        )


def test_complete_runtime_rejects_undeclared_optional_package(tmp_path: Path) -> None:
    inventory, paths = _inventory(tmp_path)

    def access(path: Path) -> int:
        if path == paths["optional"].resolve(strict=True):
            return 0x00000002  # FILE_WRITE_DATA
        return 0

    with pytest.raises(PermissionError, match="immutable Python/WLMCP runtime"):
        assert_approved_host_runtime_immutable(
            paths["package"],
            inventory=inventory,
            access_resolver=access,
        )


def test_root_identity_rejects_replaceable_runtime_ancestor(tmp_path: Path) -> None:
    inventory, paths = _inventory(tmp_path)
    repository = paths["repository"].resolve(strict=True)

    def access(path: Path) -> int:
        if path == repository.parent:
            return 0x00000040  # FILE_DELETE_CHILD
        return 0

    with pytest.raises(PermissionError, match="immutable Python/WLMCP runtime"):
        assert_approved_host_runtime_immutable(
            paths["package"],
            inventory=inventory,
            access_resolver=access,
        )


def test_ancestor_sibling_creation_does_not_false_positive(tmp_path: Path) -> None:
    inventory, paths = _inventory(tmp_path)
    repository_parent = paths["repository"].resolve(strict=True).parent

    result = assert_approved_host_runtime_immutable(
        paths["package"],
        inventory=inventory,
        access_resolver=lambda path: 0x00000002 if path == repository_parent else 0,
    )

    assert result["scope"] == "complete-runtime"


def test_runtime_paths_include_editable_launchers_and_repository(tmp_path: Path) -> None:
    inventory, paths = _inventory(tmp_path)
    directories, ancestors, files, _versions = _runtime_paths(
        paths["package"],
        inventory=inventory,
    )

    assert paths["repository"].resolve(strict=True) in directories
    assert paths["repository"].resolve(strict=True).parent in ancestors
    assert (paths["repository"] / "run-server.ps1").resolve(strict=True) in files
    assert (paths["repository"] / "run-approvals.ps1").resolve(strict=True) in files
    assert paths["startup"].resolve(strict=True) in files
    assert paths["optional"].resolve(strict=True) in files


def test_complete_runtime_accepts_read_execute_only_model(tmp_path: Path) -> None:
    inventory, paths = _inventory(tmp_path)
    result = assert_approved_host_runtime_immutable(
        paths["package"],
        inventory=inventory,
        access_resolver=lambda _path: 0x001200A0,  # FILE_GENERIC_EXECUTE
    )

    assert result["scope"] == "complete-runtime"
    assert result["file_count"] >= 4
    assert result["digest"]


@pytest.mark.skipif(os.name != "nt", reason="Windows effective-access integration")
def test_windows_effective_access_detects_user_writable_temp_file(tmp_path: Path) -> None:
    target = tmp_path / "writable.bin"
    target.write_bytes(b"test")

    assert windows_effective_runtime_access(target) & _MUTATING_ACCESS_MASK


def test_executor_blocks_approved_host_before_worker_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
        approved_host_enabled=True,
    )
    settings.ensure_directories()
    audit = AuditStore(settings)
    executor = Executor(settings, audit)
    operation_id = audit.create_operation(
        tool_name="host-runtime-gate",
        tier="approved_host",
        status="queued",
        cwd=str(workspace),
        request={},
    )

    def rejected() -> dict[str, object]:
        raise PermissionError("runtime is mutable")

    spawned = False

    def forbidden_spawn(*_args: object, **_kwargs: object) -> object:
        nonlocal spawned
        spawned = True
        raise AssertionError("worker must not spawn before runtime immutability passes")

    monkeypatch.setattr(
        "windows_local_mcp.executor.assert_approved_host_runtime_immutable",
        rejected,
    )
    monkeypatch.setattr("windows_local_mcp.executor.subprocess.Popen", forbidden_spawn)

    with pytest.raises(PermissionError, match="runtime is mutable"):
        executor.launch(operation_id, 0)

    assert spawned is False
    events = audit.get_operation(operation_id, include_events=True)["events"]
    assert any(
        event["event_type"] == "approved_host_runtime_immutability_failed"
        for event in events
    )


def test_executor_does_not_apply_host_runtime_gate_to_broker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace-broker"
    workspace.mkdir()
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data-broker",
        protect_data_dir_acl=False,
    )
    settings.ensure_directories()
    audit = AuditStore(settings)
    executor = Executor(settings, audit)
    operation_id = audit.create_operation(
        tool_name="broker-runtime-control",
        tier="broker",
        status="queued",
        cwd=str(workspace),
        request={},
    )

    gate_called = False

    def forbidden_gate() -> dict[str, object]:
        nonlocal gate_called
        gate_called = True
        raise AssertionError("Broker must not require the Approved Host runtime gate")

    def stop_after_gate(*_args: object, **_kwargs: object) -> tuple[Path, str]:
        raise RuntimeError("broker reached normal worker-context creation")

    monkeypatch.setattr(
        "windows_local_mcp.executor.assert_approved_host_runtime_immutable",
        forbidden_gate,
    )
    monkeypatch.setattr(
        "windows_local_mcp.executor.create_worker_context",
        stop_after_gate,
    )

    with pytest.raises(RuntimeError, match="normal worker-context creation"):
        executor.launch(operation_id, 0)

    assert gate_called is False
