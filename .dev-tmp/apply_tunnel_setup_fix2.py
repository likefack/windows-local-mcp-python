from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8-sig")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one match, got {count}: {old[:100]!r}")
    target.write_text(text.replace(old, new), encoding="utf-8-sig" if path.endswith(".ps1") else "utf-8")


# Also probe the conventional USERPROFILE\\OneDrive location even when the
# OneDrive environment variable is not registered.
replace_once(
    "secure-mcp-tunnel.ps1",
    '''    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $null = $downloadRoots.Add((Join-Path $env:USERPROFILE "Desktop"))
        $null = $downloadRoots.Add((Join-Path $env:USERPROFILE "Downloads"))
    }
''',
    '''    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $null = $downloadRoots.Add((Join-Path $env:USERPROFILE "Desktop"))
        $null = $downloadRoots.Add((Join-Path $env:USERPROFILE "Downloads"))
        $null = $downloadRoots.Add((Join-Path $env:USERPROFILE "OneDrive\\Desktop"))
        $null = $downloadRoots.Add((Join-Path $env:USERPROFILE "OneDrive\\Downloads"))
    }
''',
)

# Prefer pwsh for generic helper tests on hosted runners. Dedicated tests below
# still exercise Windows PowerShell 5.1 where that compatibility is the subject.
replace_once(
    "tests/test_tunnel_setup_diagnostics.py",
    '''def _shell() -> str:
    shell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
''',
    '''def _shell() -> str:
    shell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
''',
)

# Avoid module-autoload dependence in the redaction regression.
replace_once(
    "tests/test_tunnel_setup_diagnostics.py",
    '''$secretText = 'sk-test-secret-1234567890'
$secure = ConvertTo-SecureString -String $secretText -AsPlainText -Force
$json = @{{
''',
    '''$secretText = 'sk-test-secret-1234567890'
$secure = [Security.SecureString]::new()
foreach ($character in $secretText.ToCharArray()) {{ $secure.AppendChar($character) }}
$secure.MakeReadOnly()
$json = @{{
''',
)

# Add a diagnostic assertion for the pre-existing profile_binding failure so a
# hosted Windows run shows the exact expected/generated command forms.
path = Path("tests/test_tunnel_setup_diagnostics.py")
text = path.read_text(encoding="utf-8")
text += r'''

@pytest.mark.skipif(os.name != "nt", reason="Windows profile matching diagnostics")
def test_generated_profile_matches_localmcp_command(tmp_path: Path) -> None:
    profile = tmp_path / "profile.yaml"
    config = tmp_path / "config.toml"
    config.write_text('workspace_root = "C:\\\\Users\\\\Public\\\\workspace"\n', encoding="utf-8")
    server = ROOT / "run-server.ps1"
    command = f"""
$ErrorActionPreference = 'Stop'
. {_ps_literal(HELPER)}
$pid = {_ps_literal(tmp_path / 'state' / 'tunnel.pid')}
$health = {_ps_literal(tmp_path / 'state' / 'tunnel.health')}
$content = New-TunnelProfileContent -TunnelId 'tunnel_0123456789abcdef0123456789abcdef' -ServerScript {_ps_literal(server)} -ConfigPath {_ps_literal(config)} -PidFile $pid -HealthUrlFile $health
[IO.File]::WriteAllText({_ps_literal(profile)}, $content, [Text.UTF8Encoding]::new($false))
$info = Get-TunnelProfileInfo -Path {_ps_literal(profile)} -ServerScript {_ps_literal(server)} -ConfigPath {_ps_literal(config)}
$expectedServer = ConvertTo-TunnelCommandArgument -Value ([IO.Path]::GetFullPath({_ps_literal(server)}))
$expectedConfig = ConvertTo-TunnelCommandArgument -Value ([IO.Path]::GetFullPath({_ps_literal(config)}))
$expectedCommand = ConvertTo-TunnelYamlScalar -Value "powershell.exe -NoProfile -File $expectedServer -Config $expectedConfig"
if (-not $info.MatchesLocalMcp) {{
    throw ("profile mismatch`nEXPECTED=command: " + $expectedCommand + "`nCONTENT=`n" + $content)
}}
'profile-match-ok'
"""
    completed = _run(command)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "profile-match-ok" in output
'''
path.write_text(text, encoding="utf-8")
