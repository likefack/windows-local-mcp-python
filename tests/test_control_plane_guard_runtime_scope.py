from pathlib import Path

from windows_local_mcp.control_plane_guard import _wlmcp_package_root


def test_control_plane_runtime_scope_stays_inside_wlmcp_package(tmp_path: Path) -> None:
    site_packages = tmp_path / "runtime" / "Lib" / "site-packages"
    package = site_packages / "windows_local_mcp"
    module = package / "control_plane_guard.py"
    package.mkdir(parents=True)
    module.write_text("# probe\n", encoding="utf-8")
    unrelated_dependency = site_packages / "unrelated_dependency"
    unrelated_dependency.mkdir()

    assert _wlmcp_package_root(module) == package.resolve(strict=True)
    assert unrelated_dependency not in _wlmcp_package_root(module).parents
