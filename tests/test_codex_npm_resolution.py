from __future__ import annotations

import os
from pathlib import Path

import pytest

from windows_local_mcp import sandbox_backend
from windows_local_mcp.config import Settings
from windows_local_mcp.sandbox_backend import (
    ApprovedSandboxUnavailable,
    resolve_codex_sandbox_backend,
)


def _settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    settings = Settings(
        workspace_root=workspace,
        data_dir=tmp_path / "data",
        protect_data_dir_acl=False,
    )
    # This test exercises executable resolution only. Avoid the repository-wide filesystem
    # semantics probe so a shared Windows temp ACL cannot obscure that result.
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    assert settings.sandbox_scratch_dir is not None
    settings.sandbox_scratch_dir.mkdir(parents=True, exist_ok=True)
    return settings


def _write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_bytes(content)


def _npm_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    native: bool = True,
    helper: bool = True,
    workspace_prefix: bool = False,
) -> tuple[Settings, Path]:
    settings = _settings(tmp_path)
    prefix = (settings.workspace_root if workspace_prefix else tmp_path) / "npm"
    package_root = prefix / "node_modules" / "@openai" / "codex"
    target_root = package_root / "node_modules" / "@openai" / "codex-win32-x64"
    binary_dir = target_root / "vendor" / "x86_64-pc-windows-msvc" / "bin"
    native_path = binary_dir / "codex.exe"
    helper_path = binary_dir / "codex-code-mode-host.exe"

    _write(
        package_root / "package.json",
        '{"name":"@openai/codex",'
        '"bin":{"codex":"bin/codex.js"},'
        '"optionalDependencies":{"@openai/codex-win32-x64":'
        '"npm:@openai/codex@0.146.0-win32-x64"}}',
    )
    _write(package_root / "bin" / "codex.js", "// locator fixture")
    _write(
        target_root / "package.json",
        '{"name":"@openai/codex","version":"0.146.0-win32-x64",'
        '"os":["win32"],"cpu":["x64"],"files":["vendor"]}',
    )
    if native:
        _write(native_path, b"native codex")
    if helper:
        _write(helper_path, b"native code mode host")

    # The wrapper contents are intentionally unusable. They may locate the package but
    # must never be launched as the trusted Sandbox executable.
    for wrapper_name in ("codex.cmd", "codex.ps1", "codex"):
        _write(prefix / wrapper_name, "this wrapper must not be executed")

    appdata = (settings.workspace_root if workspace_prefix else tmp_path) / "appdata"
    localappdata = (settings.workspace_root if workspace_prefix else tmp_path) / "localappdata"
    userprofile = (settings.workspace_root if workspace_prefix else tmp_path) / "userprofile"
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.setenv("LOCALAPPDATA", str(localappdata))
    monkeypatch.setenv("USERPROFILE", str(userprofile))
    monkeypatch.setenv("HOME", str(userprofile))
    monkeypatch.setenv("PATH", str(prefix))
    monkeypatch.delenv("PROCESSOR_ARCHITEW6432", raising=False)
    monkeypatch.setenv("PROCESSOR_ARCHITECTURE", "AMD64")
    for name in ("PROGRAMW6432", "PROGRAMFILES", "PROGRAMFILES(X86)"):
        monkeypatch.delenv(name, raising=False)
    return settings, native_path


def _patch_native_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sandbox_backend,
        "_openai_authenticode_identity",
        lambda _path: {
            "status": "Valid",
            "subject": 'CN="OpenAI OpCo, LLC"',
            "thumbprint": "A" * 40,
        },
    )
    monkeypatch.setattr(
        sandbox_backend,
        "probe_codex_version",
        lambda *_: "0.146.0",
    )


@pytest.mark.skipif(os.name != "nt", reason="Codex Sandbox backend is Windows-only")
def test_npm_wrappers_locate_signed_native_backend_without_being_executed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, native_path = _npm_fixture(tmp_path, monkeypatch)
    _patch_native_verification(monkeypatch)

    backend = resolve_codex_sandbox_backend(settings)

    assert backend.executable == str(native_path.resolve())
    assert backend.provenance == "npm-global-codex-package"
    assert backend.version == "0.146.0"
    assert [helper.name for helper in backend.helpers] == ["codex-code-mode-host.exe"]
    assert backend.executable.endswith(
        "@openai\\codex-win32-x64\\vendor\\x86_64-pc-windows-msvc\\bin\\codex.exe"
    )


@pytest.mark.skipif(os.name != "nt", reason="Codex Sandbox backend is Windows-only")
def test_npm_native_backend_requires_complete_native_dependency_closure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, _ = _npm_fixture(tmp_path, monkeypatch, native=False)
    _patch_native_verification(monkeypatch)

    with pytest.raises(ApprovedSandboxUnavailable, match="not found or was not accessible"):
        resolve_codex_sandbox_backend(settings)

    settings, _ = _npm_fixture(tmp_path / "signature", monkeypatch)
    _patch_native_verification(monkeypatch)
    monkeypatch.setattr(
        sandbox_backend,
        "_openai_authenticode_identity",
        lambda _path: (_ for _ in ()).throw(
            ApprovedSandboxUnavailable("not signed by OpenAI")
        ),
    )
    with pytest.raises(ApprovedSandboxUnavailable, match="not found or was not accessible"):
        resolve_codex_sandbox_backend(settings)


@pytest.mark.skipif(os.name != "nt", reason="Codex Sandbox backend is Windows-only")
def test_workspace_controlled_npm_wrapper_and_package_are_not_adopted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, _ = _npm_fixture(tmp_path, monkeypatch, workspace_prefix=True)
    monkeypatch.setattr(
        sandbox_backend,
        "_openai_authenticode_identity",
        lambda _path: (_ for _ in ()).throw(
            AssertionError("workspace candidate must be rejected before signature probing")
        ),
    )

    with pytest.raises(ApprovedSandboxUnavailable, match="not found or was not accessible"):
        resolve_codex_sandbox_backend(settings)


@pytest.mark.skipif(os.name != "nt", reason="Codex Sandbox backend is Windows-only")
def test_existing_desktop_install_resolution_keeps_its_helper_closure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    install_dir = tmp_path / "localappdata" / "OpenAI" / "Codex" / "bin" / "0.150.0"
    native_path = install_dir / "codex.exe"
    _write(native_path, b"desktop codex")
    _write(install_dir / "codex-command-runner.exe", b"desktop runner")
    _write(install_dir / "codex-windows-sandbox-setup.exe", b"desktop setup")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "userprofile"))
    monkeypatch.setenv("HOME", str(tmp_path / "userprofile"))
    monkeypatch.setenv("PATH", "")
    _patch_native_verification(monkeypatch)

    backend = resolve_codex_sandbox_backend(settings)

    assert backend.provenance == "openai-codex-desktop-install-root"
    assert [helper.name for helper in backend.helpers] == [
        "codex-command-runner.exe",
        "codex-windows-sandbox-setup.exe",
    ]
    assert backend.executable == str(native_path.resolve())


@pytest.mark.skipif(os.name != "nt", reason="Codex Sandbox backend is Windows-only")
def test_existing_standalone_install_resolution_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    userprofile = tmp_path / "userprofile"
    install_dir = userprofile / ".codex" / "packages" / "standalone" / "current" / "bin"
    native_path = install_dir / "codex.exe"
    _write(native_path, b"standalone codex")
    _write(install_dir / "codex-command-runner.exe", b"standalone runner")
    _write(install_dir / "codex-windows-sandbox-setup.exe", b"standalone setup")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setenv("USERPROFILE", str(userprofile))
    monkeypatch.setenv("HOME", str(userprofile))
    monkeypatch.setenv("PATH", "")
    _patch_native_verification(monkeypatch)

    backend = resolve_codex_sandbox_backend(settings)

    assert backend.provenance == "codex-managed-standalone-root"
    assert backend.executable == str(native_path.resolve())


@pytest.mark.skipif(os.name != "nt", reason="Codex Sandbox backend is Windows-only")
def test_explicit_npm_native_path_uses_npm_dependency_closure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, native_path = _npm_fixture(tmp_path, monkeypatch)
    settings.approved_sandbox_codex_path = native_path
    monkeypatch.setenv("PATH", "")
    _patch_native_verification(monkeypatch)

    backend = resolve_codex_sandbox_backend(settings)

    assert backend.executable == str(native_path.resolve())
    assert backend.provenance == "explicit-trusted-local-config"
    assert [helper.name for helper in backend.helpers] == ["codex-code-mode-host.exe"]
