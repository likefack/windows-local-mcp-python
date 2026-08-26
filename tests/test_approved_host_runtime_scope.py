from __future__ import annotations

import os
from importlib import machinery
from pathlib import Path

import pytest

from windows_local_mcp import approved_host_policy, runtime_immutability, runtime_trust
from windows_local_mcp.runtime_trust import RuntimeTrustInventory


def _inventory(
    *,
    namespace_roots: tuple[Path, ...] = (),
    security_paths: tuple[Path, ...] = (),
) -> RuntimeTrustInventory:
    return RuntimeTrustInventory(
        trees=(),
        namespace_roots=namespace_roots,
        security_paths=security_paths,
        files=(),
        distributions=(),
    )


def test_namespace_ignores_non_importable_reparse_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "namespace"
    root.mkdir()
    alias = root / "python3.exe"
    alias.write_bytes(b"MZ")
    original = runtime_trust._is_reparse
    monkeypatch.setattr(
        runtime_trust,
        "_is_reparse",
        lambda path: path == alias or original(path),
    )

    record = runtime_trust._namespace_records((root,))[0]

    assert record["entries"] == []


@pytest.mark.parametrize(
    "name",
    ["shadow.py", f"native{machinery.EXTENSION_SUFFIXES[0]}"],
)
def test_namespace_rejects_importable_reparse_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    root = tmp_path / "namespace"
    root.mkdir()
    candidate = root / name
    candidate.write_bytes(b"payload")
    original = runtime_trust._is_reparse
    monkeypatch.setattr(
        runtime_trust,
        "_is_reparse",
        lambda path: path == candidate or original(path),
    )

    with pytest.raises(RuntimeError, match="trusted import namespace contains a reparse point"):
        runtime_trust._namespace_records((root,))


def test_namespace_rejects_importable_reparse_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "namespace"
    root.mkdir()
    package = root / "optional_plugin"
    package.mkdir()
    original = runtime_trust._is_reparse
    monkeypatch.setattr(
        runtime_trust,
        "_is_reparse",
        lambda path: path == package or original(path),
    )

    with pytest.raises(RuntimeError, match="trusted import namespace contains a reparse point"):
        runtime_trust._namespace_records((root,))


def test_security_path_is_not_recursively_promoted_to_runtime_tree(tmp_path: Path) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    security_root = tmp_path / "python-root"
    security_root.mkdir()
    unrelated = security_root / "unrelated.exe"
    unrelated.write_bytes(b"mutable but not startup active")
    inventory = _inventory(security_paths=(security_root,))

    result = runtime_immutability.assert_approved_host_runtime_immutable(
        package_root,
        inventory=inventory,
        access_resolver=lambda path: 0x00000002 if path == unrelated else 0,
    )

    assert result["directory_count"] == 1
    assert result["file_count"] == 0


def test_existing_optional_namespace_package_remains_immutable(
    tmp_path: Path,
) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    namespace = tmp_path / "site-packages"
    dependency = namespace / "optional_plugin"
    dependency.mkdir(parents=True)
    payload = dependency / "__init__.py"
    payload.write_text("VALUE = 1\n", encoding="utf-8")
    inventory = _inventory(namespace_roots=(namespace,))

    with pytest.raises(PermissionError, match="immutable Python/WLMCP runtime"):
        runtime_immutability.assert_approved_host_runtime_immutable(
            package_root,
            inventory=inventory,
            access_resolver=lambda path: 0x00000002 if path == payload else 0,
        )


@pytest.mark.skipif(os.name != "nt", reason="Approved Host runtime verification is Windows-only")
def test_runtime_verification_requires_python_isolated_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime_immutability, "_runtime_is_isolated", lambda: False)

    with pytest.raises(RuntimeError, match=r"isolated mode \(-I\)"):
        approved_host_policy.verify_approved_host_runtime_immutability_only()
