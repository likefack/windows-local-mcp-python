from __future__ import annotations

from pathlib import Path

import pytest

from windows_local_mcp import runtime_immutability
from windows_local_mcp.runtime_trust import RuntimeTree, RuntimeTrustInventory


def _production_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path]:
    repository = tmp_path / "repo"
    source_root = repository / "src"
    package = source_root / "windows_local_mcp"
    package.mkdir(parents=True)
    runtime_module = package / "runtime_immutability.py"
    runtime_module.write_text("# runtime\n", encoding="utf-8")
    (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repository / "pyproject.toml").write_text("[project]\nname='test'\n", encoding="utf-8")
    (repository / "run-server.ps1").write_text("Write-Output test\n", encoding="utf-8")
    (repository / "run-approvals.ps1").write_text("Write-Output test\n", encoding="utf-8")

    venv = tmp_path / "venv"
    venv_python = venv / "Scripts" / "python.exe"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_bytes(b"MZ venv")
    site_root = venv / "Lib" / "site-packages"
    site_root.mkdir(parents=True)

    base = tmp_path / "base"
    base_python = base / "python.exe"
    base.mkdir()
    base_python.write_bytes(b"MZ base")

    inventory = RuntimeTrustInventory(
        trees=(RuntimeTree(package),),
        namespace_roots=(source_root, site_root),
        security_paths=(source_root, site_root, venv, base),
        files=(venv_python, base_python),
        distributions=(("pydantic", "2.test"),),
    )

    monkeypatch.setattr(runtime_immutability, "__file__", str(runtime_module))
    monkeypatch.setattr(runtime_immutability.sys, "executable", str(venv_python))
    monkeypatch.setattr(runtime_immutability.sys, "prefix", str(venv))
    monkeypatch.setattr(runtime_immutability.sys, "base_prefix", str(base))
    monkeypatch.setattr(
        runtime_immutability.sys,
        "_base_executable",
        str(base_python),
        raising=False,
    )
    monkeypatch.setattr(
        runtime_immutability,
        "build_runtime_trust_inventory",
        lambda _package: inventory,
    )
    return package, repository


def test_production_runtime_paths_keep_distant_parent_as_replacement_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, repository = _production_inventory(tmp_path, monkeypatch)

    directories, ancestors, files, _versions = runtime_immutability._runtime_paths(package)

    repository = repository.resolve(strict=True)
    distant_parent = repository.parent
    assert repository in directories
    assert distant_parent in ancestors
    assert distant_parent not in directories
    assert (repository / "run-server.ps1").resolve(strict=True) in files
    assert (repository / "run-approvals.ps1").resolve(strict=True) in files


def test_production_gate_allows_sibling_creation_but_rejects_runtime_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, repository = _production_inventory(tmp_path, monkeypatch)
    distant_parent = repository.resolve(strict=True).parent

    result = runtime_immutability.assert_approved_host_runtime_immutable(
        package,
        access_resolver=lambda path: 0x00000002 if path == distant_parent else 0,
    )
    assert result["scope"] == "complete-runtime"

    with pytest.raises(PermissionError, match="immutable Python/WLMCP runtime"):
        runtime_immutability.assert_approved_host_runtime_immutable(
            package,
            access_resolver=lambda path: 0x00000040 if path == distant_parent else 0,
        )
