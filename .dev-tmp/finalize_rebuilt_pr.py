from __future__ import annotations

from pathlib import Path


def read(path: Path) -> tuple[str, bool]:
    raw = path.read_bytes()
    bom = raw.startswith(b"\xef\xbb\xbf")
    if bom:
        raw = raw[3:]
    return raw.decode("utf-8"), bom


def write(path: Path, text: str, bom: bool) -> None:
    raw = text.encode("utf-8")
    if bom:
        raw = b"\xef\xbb\xbf" + raw
    path.write_bytes(raw)


def replace_once(path: Path, old: str, new: str) -> None:
    text, bom = read(path)
    old_native = old.replace("\n", "\r\n") if "\r\n" in text and "\r\n" not in old else old
    new_native = new.replace("\n", "\r\n") if "\r\n" in text and "\r\n" not in new else new
    count = text.count(old_native)
    if count != 1:
        raise RuntimeError(f"{path}: expected one target, found {count}")
    write(path, text.replace(old_native, new_native, 1), bom)


# 1) Latest-main settings test: compare filesystem identity, not Windows short/long spelling.
local_launchers = Path("tests/test_local_launchers.py")
replace_once(
    local_launchers,
    "import tempfile\nfrom pathlib import Path\n",
    "import tempfile\nimport tomllib\nfrom pathlib import Path\n",
)
replace_once(
    local_launchers,
    '''    assert f'workspace_root = "{toml_path(new_workspace)}"' in config.read_text(
        encoding="utf-8"
    ), output
    assert f'data_dir = "{toml_path(new_data_dir)}"' in config.read_text(encoding="utf-8")
''',
    '''    updated = tomllib.loads(config.read_text(encoding="utf-8"))
    assert os.path.samefile(updated["workspace_root"], new_workspace), output
    assert os.path.samefile(updated["data_dir"], new_data_dir), output
''',
)

# 2) Latest-main normal-launcher E2E: provision the runtime contract in CI only when
# the checkout has no developer .venv, and remove only the runtime created by this test.
mcp_stdio = Path("tests/test_mcp_stdio_integration.py")
replace_once(
    mcp_stdio,
    '''def _ps_literal(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher and ACL integration")
''',
    '''def _ps_literal(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _ensure_launcher_runtime(repository_root: Path) -> bool:
    development_python = repository_root / ".venv" / "Scripts" / "python.exe"
    if development_python.is_file():
        return False
    development_root = repository_root / ".venv"
    if development_root.exists():
        pytest.skip("repository .venv exists but has no launcher Python; test will not modify it")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "venv",
            "--system-site-packages",
            "--without-pip",
            str(development_root),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
        shell=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert development_python.is_file()
    return True


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher and ACL integration")
''',
)
replace_once(
    mcp_stdio,
    '''"""
    try:
        configured = subprocess.run(
''',
    '''"""
    created_development_runtime = False
    try:
        configured = subprocess.run(
''',
)
replace_once(
    mcp_stdio,
    '''        marker = data / ".acl-policy.json"
        assert marker.is_file()

        async def exercise_launcher() -> None:
''',
    '''        marker = data / ".acl-policy.json"
        assert marker.is_file()

        created_development_runtime = _ensure_launcher_runtime(repository_root)

        async def exercise_launcher() -> None:
''',
)
replace_once(
    mcp_stdio,
    '''            shell=False,
        )


def test_real_stdio_tools_list_and_file_round_trip(tmp_path: Path) -> None:
''',
    '''            shell=False,
        )
        if created_development_runtime:
            shutil.rmtree(repository_root / ".venv", ignore_errors=True)


def test_real_stdio_tools_list_and_file_round_trip(tmp_path: Path) -> None:
''',
)

# 3) Fix only the two new regression tests: explicit success after environment cleanup,
# and a non-empty harmless forbidden-root fixture matching the PowerShell contract.
tunnel_tests = Path("tests/test_tunnel_integration.py")
replace_once(
    tunnel_tests,
    '''    if ($null -eq $oldBin) {{ Remove-Item Env:TUNNEL_CLIENT_BIN -ErrorAction SilentlyContinue }} else {{ $env:TUNNEL_CLIENT_BIN = $oldBin }}
}}
"""
''',
    '''    if ($null -eq $oldBin) {{ Remove-Item Env:TUNNEL_CLIENT_BIN -ErrorAction SilentlyContinue }} else {{ $env:TUNNEL_CLIENT_BIN = $oldBin }}
}}
exit 0
"""
''',
)
replace_once(
    tunnel_tests,
    '''function Read-Host {{ param([string]$Prompt); return $script:selectionValue }}
function Read-YesNo {{ param([string]$Prompt, [bool]$Default = $true); return $true }}
$result = Select-TunnelClient -State $null -ForbiddenRoots @()
$expected = [IO.Path]::GetFullPath({_ps_literal(expected)})
''',
    '''function Read-Host {{ param([string]$Prompt); return $script:selectionValue }}
function Read-YesNo {{ param([string]$Prompt, [bool]$Default = $true); return $true }}
$forbiddenRoot = Join-Path {_ps_literal(tmp_path)} 'forbidden'
New-Item -ItemType Directory -Path $forbiddenRoot -Force | Out-Null
$result = Select-TunnelClient -State $null -ForbiddenRoots @($forbiddenRoot)
$expected = [IO.Path]::GetFullPath({_ps_literal(expected)})
''',
)

# Normalize only touched Python test files to a single EOF newline.
for path in (local_launchers, mcp_stdio, tunnel_tests):
    text, bom = read(path)
    write(path, text.rstrip() + "\n", bom)

print("rebuilt PR final test/harness adjustments applied")
