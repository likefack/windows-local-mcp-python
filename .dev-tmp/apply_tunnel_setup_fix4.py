from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8-sig")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one match, got {count}: {old[:120]!r}")
    target.write_text(text.replace(old, new), encoding="utf-8-sig" if path.endswith(".ps1") else "utf-8")


helper = "secure-mcp-tunnel.ps1"

old_block = '''    $matchesLocalMcp = $false
    if (-not [string]::IsNullOrWhiteSpace($ServerScript) -and -not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        try {
            $expectedServer = ConvertTo-TunnelCommandArgument -Value ([IO.Path]::GetFullPath($ServerScript))
            $expectedConfig = ConvertTo-TunnelCommandArgument -Value ([IO.Path]::GetFullPath($ConfigPath))
            $expectedCommand = ConvertTo-TunnelYamlScalar -Value "powershell.exe -NoProfile -File $expectedServer -Config $expectedConfig"
            $matchesLocalMcp = $content.IndexOf("command: $expectedCommand", [StringComparison]::OrdinalIgnoreCase) -ge 0
        } catch {
            $matchesLocalMcp = $false
        }
    }
'''
new_block = '''    $matchesLocalMcp = $false
    if (-not [string]::IsNullOrWhiteSpace($ServerScript) -and -not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        try {
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
    }
'''
replace_once(helper, old_block, new_block)

anchor = '''function New-TunnelProfileContent {
'''
helper_fn = '''function Get-TunnelComparablePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path -match '[\\r\\n]') {
        throw "Tunnel command の path に改行は使用できません。"
    }
    $full = [IO.Path]::GetFullPath($Path.Replace('/', [IO.Path]::DirectorySeparatorChar))
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Tunnel command の path は通常のファイルである必要があります。"
    }
    # PowerShell's filesystem provider expands an existing Windows 8.3 alias
    # (for example RUNNER~1) to the file's normal FullName. This lets us accept
    # path spelling aliases only when both sides resolve to the same concrete
    # existing file, while still rejecting a command that targets another file.
    return ([IO.Path]::GetFullPath($item.FullName)).TrimEnd('\\', '/')
}

function New-TunnelProfileContent {
'''
replace_once(helper, anchor, helper_fn)

# Add security-oriented command-binding coverage: equivalent slash/path spelling
# is accepted, but an alternate config target is not.
path = Path("tests/test_tunnel_setup_diagnostics.py")
text = path.read_text(encoding="utf-8")
text += r'''

@pytest.mark.skipif(os.name != "nt", reason="Windows profile command binding")
def test_profile_command_binding_rejects_different_config(tmp_path: Path) -> None:
    profile = tmp_path / "profile.yaml"
    config = tmp_path / "config.toml"
    other_config = tmp_path / "other.toml"
    config.write_text('workspace_root = "C:\\\\Users\\\\Public\\\\workspace"\n', encoding="utf-8")
    other_config.write_text('workspace_root = "C:\\\\Users\\\\Public\\\\other"\n', encoding="utf-8")
    server = ROOT / "run-server.ps1"
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(HELPER)}
$content = New-TunnelProfileContent -TunnelId 'tunnel_0123456789abcdef0123456789abcdef' -ServerScript {_ps_literal(server)} -ConfigPath {_ps_literal(config)} -PidFile {_ps_literal(tmp_path / 'pid')} -HealthUrlFile {_ps_literal(tmp_path / 'health')}
[IO.File]::WriteAllText({_ps_literal(profile)}, $content, [Text.UTF8Encoding]::new($false))
$valid = Get-TunnelProfileInfo -Path {_ps_literal(profile)} -ServerScript {_ps_literal(server)} -ConfigPath {_ps_literal(config)}
if (-not $valid.MatchesLocalMcp) {{ throw 'expected command was rejected' }}
$wrong = Get-TunnelProfileInfo -Path {_ps_literal(profile)} -ServerScript {_ps_literal(server)} -ConfigPath {_ps_literal(other_config)}
if ($wrong.MatchesLocalMcp) {{ throw 'different config target was accepted' }}
'command-binding-ok'
"""
    completed = _run(command)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "command-binding-ok" in output
'''
path.write_text(text, encoding="utf-8")
