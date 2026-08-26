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
''',
    '''def test_existing_regular_package_remains_immutable(
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

replace_once(
    "tests/test_powershell_scripts.py",
    '''    assert completed.returncode == 0, completed.stderr or completed.stdout
''',
    '''    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_approved_host_installer_requires_program_files_base_and_install_root() -> None:
    script = (_REPOSITORY_ROOT / "install-approved-host-runtime.ps1").read_text(
        encoding="utf-8"
    )

    assert 'Assert-UnderProgramFiles -Path $InstallRoot -Label "InstallRoot"' in script
    assert 'Assert-UnderProgramFiles -Path $BasePython -Label "BasePython"' in script
    assert 'Assert-UnderProgramFiles -Path $BasePrefix -Label "sys.base_prefix"' in script
    assert '-c "import sys; print(sys.base_prefix)"' in script
    assert '"*${runtimeSid}:(OI)(CI)RX"' in script
    assert '"*S-1-5-18:(OI)(CI)F"' in script
    assert '"*S-1-5-32-544:(OI)(CI)F"' in script
''',
)

replace_section(
    "README.md",
    "## セットアップ\n",
    "## 主な機能\n",
    '''## Developer editable setup

Python 3.11 以上を使用します。repository checkout と `.venv` は通常 user が編集できる開発環境であり、Broker／Codex Sandbox の開発・テスト用です。Approved Host の production trust anchor にはなりません。`approved_host_enabled = true` のままでも runtime preflight は mutable runtime を検出して `available = false` にするため、editable 環境では Approved Host は利用できません。開発中に不要なら `approved_host_enabled = false` を推奨します。

```powershell
Set-Location C:\\dev\\windows-local-mcp-python
py -3.11 -m venv .venv
.\\.venv\\Scripts\\python.exe -m pip install -e .
Copy-Item config.example.toml config.local.toml
```

`config.local.toml` で少なくとも次を設定します。このファイルと `data_dir` は workspace 外へ置いてください。

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

開発 server は次のとおり起動します。設定が不正な場合は、workspace を操作する前に起動を拒否します。

```powershell
.\\run-server.ps1 -Config .\\config.local.toml
```

Secure MCP Tunnel には、Shell 文字列ではなく次の argv を登録します。

```text
powershell.exe -NoProfile -File C:\\dev\\windows-local-mcp-python\\run-server.ps1 -Config C:\\path\\to\\config.local.toml
```

複数 workspace は別々の `config`、`data_dir`、Sandbox scratch を使用してください。namespace marker が workspace、data_dir、実体識別子の混在を拒否します。Windows では handle から得た volume GUID 付きの物理 path も比較するため、junction／reparse point だけでなく SUBST 等の別名で同じ領域を指定した場合も起動を拒否します。

## Approved Host production setup

Approved Host を有効にする production runtime は editable checkout とは分離し、通常 user が read/execute のみ可能な非 editable install として Windows の Program Files 配下へ配置します。base Python と `sys.base_prefix` も Program Files 配下である必要があり、通常 user からの実効的な変更権限は non-elevated verification で fail closed します。

管理者 PowerShell から、Approved Host を使用する通常 Windows account を `RuntimeUser` に指定して provision します。

```powershell
.\\install-approved-host-runtime.ps1 `
  -BasePython "C:\\Program Files\\Python312\\python.exe" `
  -RuntimeUser "$env:USERDOMAIN\\$env:USERNAME"
```

installer は WLMCP を wheel から非 editable install し、production runtime の ACL を通常 runtime user = RX、SYSTEM／Administrators = Full Control に固定します。既存 runtime を更新する場合だけ `-Replace` を使用します。

install 後は管理者 shell を閉じ、Approved Host を実際に使用する通常 user の非昇格 PowerShell から runtime preflight を実行します。

```powershell
& "C:\\Program Files\\WindowsLocalMCP\\verify-approved-host-runtime.ps1"
```

成功後、production launcher から server／approval UI を起動します。

```powershell
& "C:\\Program Files\\WindowsLocalMCP\\run-server.ps1" -Config "C:\\path\\to\\config.local.toml"
& "C:\\Program Files\\WindowsLocalMCP\\run-approvals.ps1" -Config "C:\\path\\to\\config.local.toml"
```

`session_info()` の Approved Host capability は設定上の `enabled` と production runtime preflight に基づく `available` を別々に表示します。preflight が成功していても、実際の Approved Host worker 起動直前には runtime immutability gate を必ず再実行します。詳細な provision／更新／実機検証手順は `docs/APPROVED_HOST_RUNTIME.md` を参照してください。

''',
)

replace_once(
    "docs/APPROVED_HOST_RUNTIME.md",
    '''installer は wheel を `.dev-tmp\\approved-host-runtime` に build し、staging directory へ非 editable install した後、staging 全体の owner／ACL を固定してから active `InstallRoot` へ移します。通常 runtime user には RX、SYSTEM と Administrators には Full Control を与えます。
''',
    '''installer は `InstallRoot`、`BasePython`、`sys.base_prefix` が Windows の Program Files 配下であることを admission 時に要求します。そのうえで wheel を `.dev-tmp\\approved-host-runtime` に build し、staging directory へ非 editable install した後、staging 全体の owner／ACL を固定してから active `InstallRoot` へ移します。通常 runtime user には RX、SYSTEM と Administrators には Full Control を与えます。Program Files 配下という名前だけを immutability の証拠にはせず、base Python を含む実効 access は後段の non-elevated verification で再検証します。
''',
)
