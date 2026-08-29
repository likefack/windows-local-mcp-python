from __future__ import annotations

from pathlib import Path


def read_text_preserve_bom(path: Path) -> tuple[str, bool]:
    raw = path.read_bytes()
    bom = raw.startswith(b"\xef\xbb\xbf")
    if bom:
        raw = raw[3:]
    return raw.decode("utf-8"), bom


def write_text_preserve_bom(path: Path, text: str, bom: bool) -> None:
    raw = text.encode("utf-8")
    if bom:
        raw = b"\xef\xbb\xbf" + raw
    path.write_bytes(raw)


def replace_once(path: Path, old: str, new: str) -> None:
    text, bom = read_text_preserve_bom(path)
    old_native = old
    new_native = new
    if "\r\n" in text and "\r\n" not in old:
        old_native = old.replace("\n", "\r\n")
        new_native = new.replace("\n", "\r\n")
    count = text.count(old_native)
    if count != 1:
        raise RuntimeError(f"{path}: expected one replacement target, found {count}")
    write_text_preserve_bom(path, text.replace(old_native, new_native, 1), bom)


setup = Path("setup-localmcp.ps1")
secure = Path("secure-mcp-tunnel.ps1")
tunnel_tests = Path("tests/test_tunnel_integration.py")

# Python isolated mode (-I) ignores PYTHON* environment variables. Force UTF-8 at
# the interpreter level while keeping the existing PowerShell 5.1 capture/restore logic.
replace_once(
    setup,
    "$output = @(& $PythonPath @Arguments 2>&1)",
    "$output = @(& $PythonPath -X utf8 @Arguments 2>&1)",
)
replace_once(
    secure,
    "$output = @(& $PythonPath -I -B -c $probe 2>$null)",
    "$output = @(& $PythonPath -I -X utf8 -B -c $probe 2>$null)",
)

# Discover the official client in the common locations where a user is likely to
# have extracted it. Keep the scan bounded and still run every candidate through
# Resolve-TunnelExecutable and the existing forbidden-root/hash checks.
old_candidates = '''    $profileRoots = [System.Collections.Generic.List[string]]::new()
'''
new_candidates = '''    $downloadRoots = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $null = $downloadRoots.Add((Join-Path $env:USERPROFILE "Desktop"))
        $null = $downloadRoots.Add((Join-Path $env:USERPROFILE "Downloads"))
        $null = $downloadRoots.Add((Join-Path $env:USERPROFILE "OneDrive\\Desktop"))
        $null = $downloadRoots.Add((Join-Path $env:USERPROFILE "OneDrive\\Downloads"))
    }
    if (-not [string]::IsNullOrWhiteSpace($env:OneDrive)) {
        $null = $downloadRoots.Add((Join-Path $env:OneDrive "Desktop"))
        $null = $downloadRoots.Add((Join-Path $env:OneDrive "Downloads"))
    }
    foreach ($root in @($downloadRoots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $null = $paths.Add((Join-Path $root "tunnel-client.exe"))
        foreach ($directory in @(Get-ChildItem -LiteralPath $root -Directory -Force -Filter "tunnel-client*" -ErrorAction SilentlyContinue | Select-Object -First 50)) {
            $null = $paths.Add((Join-Path $directory.FullName "tunnel-client.exe"))
        }
    }

    $profileRoots = [System.Collections.Generic.List[string]]::new()
'''
replace_once(secure, old_candidates, new_candidates)

# Accept a pasted extraction directory only when its direct child is the expected
# executable; the child still goes through all existing trust/location checks.
old_select = '''        try {
            $resolved = Resolve-TunnelExecutable -Path $selection -ForbiddenRoots $ForbiddenRoots
            return [PSCustomObject]@{ Path = $resolved; Hash = Get-TunnelSha256 -Path $resolved }
'''
new_select = '''        try {
            if (Test-Path -LiteralPath $selection -PathType Container) {
                $directChild = Join-Path $selection "tunnel-client.exe"
                if (-not (Test-Path -LiteralPath $directChild -PathType Leaf)) {
                    Write-Warn "指定したフォルダー直下に tunnel-client.exe がありません。実行ファイルまで含む path を指定してください。"
                    continue
                }
                Write-Info "フォルダー直下の tunnel-client.exe を検出しました: $directChild"
                if (-not (Read-YesNo -Prompt "この tunnel-client.exe を使用しますか" -Default $true)) {
                    continue
                }
                $selection = $directChild
            }
            $resolved = Resolve-TunnelExecutable -Path $selection -ForbiddenRoots $ForbiddenRoots
            return [PSCustomObject]@{ Path = $resolved; Hash = Get-TunnelSha256 -Path $resolved }
'''
replace_once(setup, old_select, new_select)

# Compare the profile command by resolved ordinary-file identity spelling rather
# than the raw path text. This accepts Windows 8.3 aliases only when they resolve
# to the same concrete files, while retaining the exact command-shape gate.
old_scalar_boundary = '''function New-TunnelProfileContent {
'''
new_scalar_boundary = '''function Get-TunnelComparablePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path -match '[\\r\\n]') {
        throw "Tunnel command の path に改行は使用できません。"
    }
    $full = [IO.Path]::GetFullPath($Path.Replace('/', [IO.Path]::DirectorySeparatorChar))
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Tunnel command の path は通常のファイルである必要があります。"
    }
    return ([IO.Path]::GetFullPath($item.FullName)).TrimEnd('\\', '/')
}

function New-TunnelProfileContent {
'''
replace_once(secure, old_scalar_boundary, new_scalar_boundary)

old_binding = '''        try {
            $expectedServer = ConvertTo-TunnelCommandArgument -Value ([IO.Path]::GetFullPath($ServerScript))
            $expectedConfig = ConvertTo-TunnelCommandArgument -Value ([IO.Path]::GetFullPath($ConfigPath))
            $expectedCommand = ConvertTo-TunnelYamlScalar -Value "powershell.exe -NoProfile -File $expectedServer -Config $expectedConfig"
            $matchesLocalMcp = $content.IndexOf("command: $expectedCommand", [StringComparison]::OrdinalIgnoreCase) -ge 0
        } catch {
            $matchesLocalMcp = $false
        }
'''
new_binding = '''        try {
            $commandMatches = [regex]::Matches($content, '(?im)^\\s*command\\s*:\\s*(?<value>[^\\r\\n]+)\\s*$')
            if ($commandMatches.Count -eq 1) {
                $command = ConvertFrom-TunnelYamlScalar -Value $commandMatches[0].Groups["value"].Value
                $parsedCommand = [regex]::Match(
                    $command,
                    '^powershell\\.exe\\s+-NoProfile\\s+-File\\s+"(?<server>[^"\\r\\n]+)"\\s+-Config\\s+"(?<config>[^"\\r\\n]+)"$'
                )
                if ($parsedCommand.Success) {
                    $actualServer = Get-TunnelComparablePath -Path $parsedCommand.Groups["server"].Value
                    $actualConfig = Get-TunnelComparablePath -Path $parsedCommand.Groups["config"].Value
                    $expectedServer = Get-TunnelComparablePath -Path $ServerScript
                    $expectedConfig = Get-TunnelComparablePath -Path $ConfigPath
                    $matchesLocalMcp =
                        $actualServer.Equals($expectedServer, [StringComparison]::OrdinalIgnoreCase) -and
                        $actualConfig.Equals($expectedConfig, [StringComparison]::OrdinalIgnoreCase)
                }
            }
        } catch {
            $matchesLocalMcp = $false
        }
'''
replace_once(secure, old_binding, new_binding)

# Add focused behavior tests only for the retained UX additions. Existing main
# regressions already exercise UTF-8 isolated execution and 8.3 profile binding.
test_text, test_bom = read_text_preserve_bom(tunnel_tests)
marker = "def test_common_download_locations_discover_tunnel_client"
if marker in test_text:
    raise RuntimeError("focused tests already present")
append = r'''


@pytest.mark.skipif(os.name != "nt", reason="PowerShell helper is Windows-only")
def test_common_download_locations_discover_tunnel_client(tmp_path: Path) -> None:
    user_profile = tmp_path / "user profile"
    client_dir = user_profile / "Desktop" / "tunnel-client-v0.0.10-windows-amd64"
    client_dir.mkdir(parents=True)
    expected = client_dir / "tunnel-client.exe"
    shutil.copy2(os.environ.get("ComSpec", r"C:\Windows\System32\cmd.exe"), expected)
    state_root = tmp_path / "state"
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(_HELPER)}
$oldUserProfile = $env:USERPROFILE
$oldOneDrive = $env:OneDrive
$oldBin = $env:TUNNEL_CLIENT_BIN
try {{
    $env:USERPROFILE = {_ps_literal(user_profile)}
    Remove-Item Env:OneDrive -ErrorAction SilentlyContinue
    Remove-Item Env:TUNNEL_CLIENT_BIN -ErrorAction SilentlyContinue
    $candidates = @(Get-TunnelClientCandidates -StateRoot {_ps_literal(state_root)} -ForbiddenRoots @())
    $expected = [IO.Path]::GetFullPath({_ps_literal(expected)})
    if (-not ($candidates | Where-Object {{ [IO.Path]::GetFullPath($_.Path).Equals($expected, [StringComparison]::OrdinalIgnoreCase) }})) {{
        throw 'Desktop extraction candidate was not discovered'
    }}
    'download-candidate-ok'
}} finally {{
    $env:USERPROFILE = $oldUserProfile
    if ($null -eq $oldOneDrive) {{ Remove-Item Env:OneDrive -ErrorAction SilentlyContinue }} else {{ $env:OneDrive = $oldOneDrive }}
    if ($null -eq $oldBin) {{ Remove-Item Env:TUNNEL_CLIENT_BIN -ErrorAction SilentlyContinue }} else {{ $env:TUNNEL_CLIENT_BIN = $oldBin }}
}}
"""
    completed = _run_powershell(command)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "download-candidate-ok" in output


@pytest.mark.skipif(os.name != "nt", reason="PowerShell setup helper is Windows-only")
def test_tunnel_client_directory_input_resolves_direct_executable(tmp_path: Path) -> None:
    client_dir = tmp_path / "tunnel client extracted"
    client_dir.mkdir()
    expected = client_dir / "tunnel-client.exe"
    shutil.copy2(os.environ.get("ComSpec", r"C:\Windows\System32\cmd.exe"), expected)
    setup = _REPOSITORY_ROOT / "setup-localmcp.ps1"
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(setup)} -FunctionsOnly
$script:selectionValue = {_ps_literal(client_dir)}
function Get-TunnelClientCandidates {{ return @() }}
function Read-Host {{ param([string]$Prompt); return $script:selectionValue }}
function Read-YesNo {{ param([string]$Prompt, [bool]$Default = $true); return $true }}
$result = Select-TunnelClient -State $null -ForbiddenRoots @()
$expected = [IO.Path]::GetFullPath({_ps_literal(expected)})
if ($null -eq $result -or -not [IO.Path]::GetFullPath($result.Path).Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {{
    throw 'directory input did not resolve its direct tunnel-client.exe child'
}}
'directory-input-ok'
"""
    completed = _run_powershell(command)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "directory-input-ok" in output
'''
write_text_preserve_bom(tunnel_tests, test_text.rstrip() + append + "\n", test_bom)

print("latest-main Tunnel UX patch applied")
