from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    with (ROOT / path).open("w", encoding="utf-8", newline="\n") as output:
        output.write(text)


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one replacement target, found {count}")
    write(path, text.replace(old, new, 1))


def replace_section(path: str, start_marker: str, end_marker: str, replacement: str) -> None:
    text = read(path)
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    write(path, text[:start] + replacement + text[end:])


def create_text(path: str, text: str) -> None:
    target = ROOT / path
    if target.exists():
        raise RuntimeError(f"{path}: already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    write(path, text)


replace_once(
    "src/windows_local_mcp/runtime_immutability.py",
    '''    The namespace directory itself remains immutable so an Approved Host child cannot add
    a new importable sibling. Regular packages are recursively immutable. Namespace-package
    directories without an ``__init__`` are pinned at the directory boundary; declared
    dependencies remain recursively covered by ``RuntimeTree`` inventory entries.
''',
    '''    The namespace directory itself remains immutable so an Approved Host child cannot add
    a new importable sibling. Every existing importable package or namespace-package directory
    is recursively immutable because modules below either form can participate in later imports.
''',
)
replace_once(
    "src/windows_local_mcp/runtime_immutability.py",
    '''        if child.is_dir():
            if kind == "package-directory":
                child_directories, child_files = _tree_paths(RuntimeTree(child))
                directories.update(child_directories)
                files.update(child_files)
            else:
                directories.add(child.resolve(strict=True))
''',
    '''        if child.is_dir():
            child_directories, child_files = _tree_paths(RuntimeTree(child))
            directories.update(child_directories)
            files.update(child_files)
''',
)

replace_once(
    "tests/test_approved_host_runtime_scope.py",
    '''    ["shadow.py", f"native{machinery.EXTENSION_SUFFIXES[0]}"],
''',
    '''    ["shadow.py", "startup.pth", f"native{machinery.EXTENSION_SUFFIXES[0]}"],
''',
)
replace_once(
    "tests/test_approved_host_runtime_scope.py",
    '''def test_existing_optional_namespace_package_remains_immutable(
    tmp_path: Path,
) -> None:
''',
    '''def test_existing_regular_package_remains_immutable(
    tmp_path: Path,
) -> None:
''',
)
replace_once(
    "tests/test_approved_host_runtime_scope.py",
    '''

@pytest.mark.skipif(os.name != "nt", reason="Approved Host production gate is Windows-only")
def test_production_gate_requires_python_isolated_mode(
''',
    '''

def test_existing_namespace_package_content_remains_immutable(tmp_path: Path) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    namespace = tmp_path / "site-packages"
    dependency = namespace / "optional_plugin"
    dependency.mkdir(parents=True)
    payload = dependency / "feature.py"
    payload.write_text("VALUE = 1\\n", encoding="utf-8")
    inventory = _inventory(namespace_roots=(namespace,))

    with pytest.raises(PermissionError, match="immutable Python/WLMCP runtime"):
        runtime_immutability.assert_approved_host_runtime_immutable(
            package_root,
            inventory=inventory,
            access_resolver=lambda path: 0x00000002 if path == payload else 0,
        )


@pytest.mark.skipif(os.name != "nt", reason="Approved Host production gate is Windows-only")
def test_production_gate_requires_python_isolated_mode(
''',
)

replace_once(
    "src/windows_local_mcp/server.py",
    '''from .risk import command_risk_facts
from .sandbox_backend import (
''',
    '''from .risk import command_risk_facts
from .runtime_immutability import assert_approved_host_runtime_immutable
from .sandbox_backend import (
''',
)
replace_once(
    "src/windows_local_mcp/server.py",
    '''
def _broker_helper_capability(program_key: str, enabled: bool) -> dict[str, Any]:
''',
    '''
def _approved_host_capability() -> dict[str, Any]:
    status: dict[str, Any] = {
        "configured": runtime.settings.approved_host_enabled,
        "enabled": runtime.settings.approved_host_enabled,
        "available": False,
        "live_verified": False,
        "windows_live_verified": False,
        "execution_time_recheck": True,
        "runtime_preflight": {"status": "not_run"},
    }
    if not runtime.settings.approved_host_enabled:
        status["unavailable_reason"] = "disabled by configuration"
        return status
    try:
        evidence = assert_approved_host_runtime_immutable()
    except Exception as error:  # noqa: BLE001 - capability display must remain available
        message = redact_text(f"{type(error).__name__}: {error}")
        status["unavailable_reason"] = message
        status["runtime_preflight"] = {"status": "failed", "error": message}
        return status

    status["available"] = True
    status["live_verified"] = True
    status["windows_live_verified"] = os.name == "nt"
    status["runtime_preflight"] = {
        "status": "passed",
        "version": evidence.get("version"),
        "scope": evidence.get("scope"),
        "path_count": evidence.get("path_count"),
        "file_count": evidence.get("file_count"),
        "directory_count": evidence.get("directory_count"),
        "ancestor_directory_count": evidence.get("ancestor_directory_count"),
        "digest": evidence.get("digest"),
    }
    return status


def _broker_helper_capability(program_key: str, enabled: bool) -> dict[str, Any]:
''',
)
replace_once(
    "src/windows_local_mcp/server.py",
    '''    codex_sandbox = _codex_sandbox_capability()
    git_helper = _broker_helper_capability("git", runtime.settings.git_enabled)
    adb_helper = _broker_helper_capability("adb", runtime.settings.adb_enabled)
    result = {
''',
    '''    codex_sandbox = _codex_sandbox_capability()
    git_helper = _broker_helper_capability("git", runtime.settings.git_enabled)
    adb_helper = _broker_helper_capability("adb", runtime.settings.adb_enabled)
    approved_host = _approved_host_capability()
    result = {
''',
)
replace_once(
    "src/windows_local_mcp/server.py",
    '''                "approved_host": {
                    "configured": runtime.settings.approved_host_enabled,
                    "enabled": runtime.settings.approved_host_enabled,
                    "available": runtime.settings.approved_host_enabled and os.name == "nt",
                    "live_verified": False,
                },
''',
    '''                "approved_host": approved_host,
''',
)

replace_once(
    "tests/test_server_operations.py",
    '''    assert "property evidence is incomplete" in status["execution_unavailable_reason"]


def test_backup_and_diff_limits_fail_before_replacement(
''',
    '''    assert "property evidence is incomplete" in status["execution_unavailable_reason"]


def test_approved_host_capability_does_not_preflight_when_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _ = load_server(tmp_path, monkeypatch)
    server.runtime.settings.approved_host_enabled = False

    def unexpected_preflight():
        raise AssertionError("disabled Approved Host must not run runtime preflight")

    monkeypatch.setattr(server, "assert_approved_host_runtime_immutable", unexpected_preflight)

    status = server._approved_host_capability()

    assert status["enabled"] is False
    assert status["available"] is False
    assert status["runtime_preflight"]["status"] == "not_run"


def test_approved_host_capability_reports_failed_runtime_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _ = load_server(tmp_path, monkeypatch)
    server.runtime.settings.approved_host_enabled = True
    monkeypatch.setattr(
        server,
        "assert_approved_host_runtime_immutable",
        lambda: (_ for _ in ()).throw(RuntimeError("runtime is mutable")),
    )

    status = server._approved_host_capability()

    assert status["enabled"] is True
    assert status["available"] is False
    assert status["runtime_preflight"]["status"] == "failed"
    assert "runtime is mutable" in status["runtime_preflight"]["error"]
    assert status["execution_time_recheck"] is True


def test_approved_host_capability_reports_passed_runtime_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _ = load_server(tmp_path, monkeypatch)
    server.runtime.settings.approved_host_enabled = True
    monkeypatch.setattr(
        server,
        "assert_approved_host_runtime_immutable",
        lambda: {
            "version": 1,
            "scope": "complete-runtime",
            "path_count": 12,
            "file_count": 5,
            "directory_count": 4,
            "ancestor_directory_count": 3,
            "digest": "a" * 64,
        },
    )

    status = server._approved_host_capability()

    assert status["enabled"] is True
    assert status["available"] is True
    assert status["live_verified"] is True
    assert status["runtime_preflight"]["status"] == "passed"
    assert status["runtime_preflight"]["digest"] == "a" * 64
    assert status["execution_time_recheck"] is True


def test_backup_and_diff_limits_fail_before_replacement(
''',
)

create_text(
    "tests/test_runtime_closure_isolation.py",
    '''from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_isolated_runtime_closure_excludes_pytest_temp_and_cwd(tmp_path: Path) -> None:
    dev_tmp = (_REPOSITORY_ROOT / ".dev-tmp").resolve()
    cwd = tmp_path.resolve()
    assert cwd.is_relative_to(dev_tmp)

    probe = r"""
import json
import sys
from pathlib import Path

from windows_local_mcp.runtime_immutability import _runtime_paths
from windows_local_mcp.runtime_trust import build_runtime_trust_inventory

cwd = Path.cwd().resolve()
dev_tmp = Path(sys.argv[1]).resolve()
inventory = build_runtime_trust_inventory()
directories, ancestors, files, _distributions = _runtime_paths(inventory=inventory)


def inside(path, root):
    path = Path(path).resolve()
    return path == root or path.is_relative_to(root)


def offenders(values, root):
    return [str(value) for value in values if inside(value, root)]

payload = {
    "isolated": int(sys.flags.isolated),
    "sys_path_cwd": offenders(sys.path, cwd),
    "sys_path_dev_tmp": offenders(sys.path, dev_tmp),
    "closure_cwd": {
        "directories": offenders(directories, cwd),
        "ancestors": offenders(ancestors, cwd),
        "files": offenders(files, cwd),
    },
    "closure_dev_tmp": {
        "directories": offenders(directories, dev_tmp),
        "ancestors": offenders(ancestors, dev_tmp),
        "files": offenders(files, dev_tmp),
    },
}
print(json.dumps(payload, sort_keys=True))
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join((str(cwd), str(dev_tmp)))
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-c", probe, str(dev_tmp)],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
        shell=False,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    payload = json.loads(completed.stdout)
    assert payload["isolated"] == 1
    assert payload["sys_path_cwd"] == []
    assert payload["sys_path_dev_tmp"] == []
    assert all(values == [] for values in payload["closure_cwd"].values())
    assert all(values == [] for values in payload["closure_dev_tmp"].values())
''',
)

replace_once(
    "install-approved-host-runtime.ps1",
    '''$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
''',
    '''$ErrorActionPreference = "Stop"

function Assert-UnderProgramFiles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\\', '/')
    $roots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramW6432
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\\', '/') } |
        Select-Object -Unique

    foreach ($root in $roots) {
        if ($candidate.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            return $candidate
        }
    }
    throw "$Label must be below a Windows Program Files directory: $candidate"
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
''',
)
replace_once(
    "install-approved-host-runtime.ps1",
    '''$SourceRoot = $PSScriptRoot
$BasePython = (Resolve-Path -LiteralPath $BasePython).Path
if (-not (Test-Path -LiteralPath $BasePython -PathType Leaf)) {
    throw "Base Python executable does not exist: $BasePython"
}

$runtimeAccount = [Security.Principal.NTAccount]::new($RuntimeUser)
''',
    '''$SourceRoot = $PSScriptRoot
$InstallRoot = Assert-UnderProgramFiles -Path $InstallRoot -Label "InstallRoot"
$BasePython = (Resolve-Path -LiteralPath $BasePython).Path
if (-not (Test-Path -LiteralPath $BasePython -PathType Leaf)) {
    throw "Base Python executable does not exist: $BasePython"
}
$BasePython = Assert-UnderProgramFiles -Path $BasePython -Label "BasePython"
$BasePrefix = ((& $BasePython -I -B -c "import sys; print(sys.base_prefix)") | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($BasePrefix)) {
    throw "Could not resolve sys.base_prefix from BasePython."
}
if (-not (Test-Path -LiteralPath $BasePrefix -PathType Container)) {
    throw "Base Python prefix does not exist: $BasePrefix"
}
$BasePrefix = Assert-UnderProgramFiles -Path $BasePrefix -Label "sys.base_prefix"

$runtimeAccount = [Security.Principal.NTAccount]::new($RuntimeUser)
''',
)
replace_once(
    "install-approved-host-runtime.ps1",
    '''    Write-Output "Base Python: $BasePython"
    Write-Output "Run verify-approved-host-runtime.ps1 from a normal non-elevated $RuntimeUser session before enabling Approved Host use."
''',
    '''    Write-Output "Base Python: $BasePython"
    Write-Output "Base Python prefix: $BasePrefix"
    Write-Output "Run verify-approved-host-runtime.ps1 from a normal non-elevated $RuntimeUser session before enabling Approved Host use."
''',
)

replace_section(
    "README.md",
    "## セットアップ\n",
    "## 主な機能\n",
    '''## Developer editable setup

Python 3.11 以上を使用します。通常の開発では repository checkout と `.venv` を user-writable のまま使用します。

```powershell
Set-Location C:\\dev\\windows-local-mcp-python
py -3.11 -m venv .venv
.\\.venv\\Scripts\\python.exe -m pip install -e .
Copy-Item config.example.toml config.local.toml
```

`config.local.toml` で少なくとも次を設定します。このファイルと `data_dir` は workspace 外へ置いてください。editable environment では Approved Host を production trust boundary として利用できないため、開発設定では無効化することを推奨します。

```toml
workspace_root = "C:\\\\dev\\\\your-project"
data_dir = "C:\\\\Users\\\\you\\\\AppData\\\\Local\\\\windows-local-mcp\\\\your-project"
protect_data_dir_acl = true
approved_host_enabled = false
```

Broker が自動実行する ADB helper は `PATH` 上の同名ファイルを使用しません。workspace、`data_dir`、Sandbox scratch の外にある絶対 path と SHA-256 を対で設定してください。未設定時は capability が有効でも実行を拒否します。

Git executable の path／SHA-256 も approved route の trust anchor として設定できますが、current v1 ではこれらを設定しても automatic Git Broker execution は有効になりません。workspace-controlled repository metadata を無承認 Git child から安全に閉じ込められることが未実証なためです。

```powershell
$gitPath = (Get-Command git.exe).Source
$gitHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $gitPath).Hash.ToLowerInvariant()
```

```toml
git_executable_path = "C:\\\\Program Files\\\\Git\\\\cmd\\\\git.exe"
git_executable_sha256 = "ここを64桁のSHA-256へ置換"
```

開発用 server は次のように起動します。設定が不正な場合は workspace を操作する前に起動を拒否します。

```powershell
.\\run-server.ps1 -Config .\\config.local.toml
```

Secure MCP Tunnel には Shell 文字列ではなく次の argv を登録します。

```text
powershell.exe -NoProfile -File C:\\dev\\windows-local-mcp-python\\run-server.ps1 -Config C:\\path\\to\\config.local.toml
```

複数 workspace は別々の `config`、`data_dir`、Sandbox scratch を使用してください。namespace marker が workspace、data_dir、実体識別子の混在を拒否します。Windows では handle から得た volume GUID 付きの物理 path も比較するため、junction／reparse point だけでなく SUBST 等の別名で同じ領域を指定した場合も起動を拒否します。

editable checkout／`.venv` は通常 user が変更できるため、Approved Host の production runtime preflight は通過しません。`approved_host_enabled = true` のまま開発 server を起動しても `session_info` では `enabled` と `available` が分離され、preflight 不合格時は `available = false` になります。

## Approved Host production setup

Approved Host を有効にする場合は editable checkout を実行基盤にせず、通常 user から変更できない non-editable runtime を `Program Files` 配下へ provisioning します。installer は WLMCP runtime を通常 user RX、Administrators／SYSTEM Full Control に固定し、`BasePython` と `sys.base_prefix` も Program Files 配下であることを要求します。実効 ACL の最終判定は必ず通常 user の non-elevated preflight で行います。

管理者 PowerShell から repository root で実行します。

```powershell
.\\install-approved-host-runtime.ps1 `
  -BasePython "C:\\Program Files\\Python312\\python.exe" `
  -RuntimeUser "$env:USERDOMAIN\\$env:USERNAME"
```

その後、管理者 shell を閉じ、Approved Host を実際に使う通常 user で次を実行します。

```powershell
& "C:\\Program Files\\WindowsLocalMCP\\verify-approved-host-runtime.ps1"
```

preflight 成功後のみ production launcher を使用します。launcher と worker は Python isolated mode `-I` を使用し、Approved Host の実行直前にも runtime immutability gate を再実行します。

```powershell
& "C:\\Program Files\\WindowsLocalMCP\\run-server.ps1" -Config "C:\\path\\to\\config.local.toml"
& "C:\\Program Files\\WindowsLocalMCP\\run-approvals.ps1" -Config "C:\\path\\to\\config.local.toml"
```

詳細な install、update、非昇格 verification、実機 smoke の前提は `docs/APPROVED_HOST_RUNTIME.md` を参照してください。

''',
)

replace_once(
    "docs/APPROVED_HOST_RUNTIME.md",
    '''`runtime` の venv だけでなく、その venv が参照する base Python も non-elevated WLMCP user から immutable である必要があります。配置場所の名前だけを trust anchor にはせず、実行前の Windows effective-access check が最終判定します。
''',
    '''`runtime` の venv だけでなく、その venv が参照する base Python も non-elevated WLMCP user から immutable である必要があります。installer は `InstallRoot`、`BasePython`、`sys.base_prefix` が Windows の Program Files 配下にあることを admission 条件として確認します。ただし配置場所の名前だけを trust anchor にはせず、実行前の Windows effective-access check が最終判定します。
''',
)
replace_once(
    "docs/APPROVED_HOST_RUNTIME.md",
    '''production launcher は `runtime\\Scripts\\python.exe` を優先し、source repository の launcher は production runtime が存在しない場合だけ `.venv` を開発用 fallback として使います。どちらも Python を `-I -B` で起動します。

## Update
''',
    '''production launcher は `runtime\\Scripts\\python.exe` を優先し、source repository の launcher は production runtime が存在しない場合だけ `.venv` を開発用 fallback として使います。どちらも Python を `-I -B` で起動します。

`session_info` の Approved Host capability は設定上の `enabled` と、runtime preflight を通過して現在利用可能かを示す `available` を分離します。`runtime_preflight.status` は `not_run`／`failed`／`passed` を返し、`passed` の場合は runtime evidence の digest と path count を表示します。この表示用 preflight は実行時 gate の代替ではなく、Approved Host command の実行直前にも `assert_approved_host_runtime_immutable()` を再実行します。

## Update
''',
)
