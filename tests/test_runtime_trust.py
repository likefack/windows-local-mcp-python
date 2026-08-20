from pathlib import Path

from windows_local_mcp.runtime_trust import (
    RuntimeTree,
    RuntimeTrustInventory,
    capture_runtime_dependency_state,
    runtime_generation_identity,
)


def _inventory(tmp_path: Path) -> tuple[RuntimeTrustInventory, dict[str, Path]]:
    source_root = tmp_path / "src"
    package = source_root / "windows_local_mcp"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")

    site_root = tmp_path / "site-packages"
    dependency = site_root / "pydantic"
    dependency.mkdir(parents=True)
    (dependency / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    native = dependency / "_core.pyd"
    native.write_bytes(b"native-v1")
    startup = site_root / "runtime-hook.pth"
    startup.write_text("# trusted startup\n", encoding="utf-8")

    unrelated = site_root / "unrelated"
    unrelated.mkdir()
    unrelated_payload = unrelated / "data.bin"
    unrelated_payload.write_bytes(b"unrelated-v1")

    inventory = RuntimeTrustInventory(
        trees=(RuntimeTree(package), RuntimeTree(dependency)),
        namespace_roots=(source_root, site_root),
        security_paths=(source_root, site_root),
        files=(startup,),
        distributions=(("pydantic", "2.test"),),
    )
    return inventory, {
        "source_root": source_root,
        "package": package,
        "site_root": site_root,
        "dependency": dependency,
        "native": native,
        "startup": startup,
        "unrelated_payload": unrelated_payload,
    }


def _capture(inventory: RuntimeTrustInventory) -> dict[str, object]:
    return capture_runtime_dependency_state(
        max_files=1000,
        max_bytes=1024 * 1024,
        inventory=inventory,
    )


def test_runtime_dependency_state_detects_import_shadow_and_startup_hook(
    tmp_path: Path,
) -> None:
    inventory, paths = _inventory(tmp_path)
    before = _capture(inventory)

    shadow = paths["source_root"] / "pydantic.py"
    shadow.write_text("raise RuntimeError('shadowed')\n", encoding="utf-8")
    after_shadow = _capture(inventory)
    assert after_shadow["digest"] != before["digest"]

    shadow.unlink()
    paths["startup"].write_text("import malicious_runtime_hook\n", encoding="utf-8")
    after_startup = _capture(inventory)
    assert after_startup["digest"] != before["digest"]


def test_runtime_dependency_state_detects_dependency_and_native_extension_changes(
    tmp_path: Path,
) -> None:
    inventory, paths = _inventory(tmp_path)
    before = _capture(inventory)

    (paths["dependency"] / "__init__.py").write_text("VALUE = 2\n", encoding="utf-8")
    after_python = _capture(inventory)
    assert after_python["digest"] != before["digest"]

    (paths["dependency"] / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    paths["native"].write_bytes(b"native-v2")
    after_native = _capture(inventory)
    assert after_native["digest"] != before["digest"]


def test_runtime_dependency_state_does_not_hash_unrelated_nested_site_package_content(
    tmp_path: Path,
) -> None:
    inventory, paths = _inventory(tmp_path)
    before = _capture(inventory)

    paths["unrelated_payload"].write_bytes(b"unrelated-v2")
    after = _capture(inventory)

    assert after["digest"] == before["digest"]


def test_runtime_generation_identity_binds_source_namespace(tmp_path: Path) -> None:
    package = tmp_path / "src" / "windows_local_mcp"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    before = runtime_generation_identity(package)

    (package.parent / "json.py").write_text("VALUE = 'shadow'\n", encoding="utf-8")
    after = runtime_generation_identity(package)

    assert after != before
