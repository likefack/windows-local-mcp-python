from __future__ import annotations

from pathlib import Path

import pytest

from windows_local_mcp.runtime_immutability import assert_approved_host_runtime_immutable
from windows_local_mcp.runtime_trust import RuntimeTree, RuntimeTrustInventory

_DELETE = 0x00010000
_FILE_DELETE_CHILD = 0x00000040
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000


def _runtime_inventory(tmp_path: Path) -> tuple[RuntimeTrustInventory, Path, Path]:
    runtime_root = tmp_path / "runtime"
    package = runtime_root / "package"
    package.mkdir(parents=True)
    payload = package / "__init__.py"
    payload.write_text("VALUE = 1\n", encoding="utf-8")
    inventory = RuntimeTrustInventory(
        trees=(RuntimeTree(package),),
        namespace_roots=(),
        security_paths=(runtime_root,),
        files=(),
        distributions=(),
    )
    return inventory, package, payload


def test_volume_root_delete_only_does_not_false_positive(tmp_path: Path) -> None:
    inventory, package, _payload = _runtime_inventory(tmp_path)
    volume_root = Path(package.anchor).resolve(strict=True)

    result = assert_approved_host_runtime_immutable(
        package,
        inventory=inventory,
        access_resolver=lambda path: _DELETE if path == volume_root else 0,
    )

    assert result["scope"] == "complete-runtime"


@pytest.mark.parametrize("access", [_FILE_DELETE_CHILD, _WRITE_DAC, _WRITE_OWNER])
def test_volume_root_still_rejects_child_or_acl_authority(
    tmp_path: Path,
    access: int,
) -> None:
    inventory, package, _payload = _runtime_inventory(tmp_path)
    volume_root = Path(package.anchor).resolve(strict=True)

    with pytest.raises(PermissionError, match="immutable Python/WLMCP runtime"):
        assert_approved_host_runtime_immutable(
            package,
            inventory=inventory,
            access_resolver=lambda path: access if path == volume_root else 0,
        )


def test_non_root_ancestor_delete_still_fails_closed(tmp_path: Path) -> None:
    inventory, package, _payload = _runtime_inventory(tmp_path)
    non_root_ancestor = tmp_path.resolve(strict=True)
    assert non_root_ancestor != Path(non_root_ancestor.anchor)

    with pytest.raises(PermissionError, match="immutable Python/WLMCP runtime"):
        assert_approved_host_runtime_immutable(
            package,
            inventory=inventory,
            access_resolver=lambda path: _DELETE if path == non_root_ancestor else 0,
        )


def test_protected_runtime_object_delete_still_fails_closed(tmp_path: Path) -> None:
    inventory, package, payload = _runtime_inventory(tmp_path)
    protected = payload.resolve(strict=True)

    with pytest.raises(PermissionError, match="immutable Python/WLMCP runtime"):
        assert_approved_host_runtime_immutable(
            package,
            inventory=inventory,
            access_resolver=lambda path: _DELETE if path == protected else 0,
        )
