from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8-sig")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one match, got {count}: {old[:100]!r}")
    target.write_text(text.replace(old, new), encoding="utf-8-sig" if path.endswith(".ps1") else "utf-8")


replace_once(
    "tests/test_tunnel_setup_diagnostics.py",
    '''$pid = {_ps_literal(tmp_path / 'state' / 'tunnel.pid')}
$health = {_ps_literal(tmp_path / 'state' / 'tunnel.health')}
$content = New-TunnelProfileContent -TunnelId 'tunnel_0123456789abcdef0123456789abcdef' -ServerScript {_ps_literal(server)} -ConfigPath {_ps_literal(config)} -PidFile $pid -HealthUrlFile $health
''',
    '''$pidPath = {_ps_literal(tmp_path / 'state' / 'tunnel.pid')}
$healthPath = {_ps_literal(tmp_path / 'state' / 'tunnel.health')}
$content = New-TunnelProfileContent -TunnelId 'tunnel_0123456789abcdef0123456789abcdef' -ServerScript {_ps_literal(server)} -ConfigPath {_ps_literal(config)} -PidFile $pidPath -HealthUrlFile $healthPath
''',
)

# On Windows tempfile may surface an 8.3 spelling while PowerShell persists the
# equivalent long spelling. Parse TOML, then compare resolved filesystem identity
# instead of raw path spelling.
path = Path("tests/test_local_launchers.py")
text = path.read_text(encoding="utf-8")
if "import tomllib\n" not in text:
    text = text.replace("import tempfile\n", "import tempfile\nimport tomllib\n", 1)
old = '''    assert f'data_dir = "{toml_path(new_data_dir)}"' in config.read_text(encoding="utf-8")
'''
new = '''    configured_data = Path(tomllib.loads(config.read_text(encoding="utf-8"))["data_dir"])
    assert configured_data.resolve() == new_data_dir.resolve()
'''
if text.count(old) != 1:
    raise RuntimeError(f"tests/test_local_launchers.py: expected one data_dir assertion, got {text.count(old)}")
path.write_text(text.replace(old, new), encoding="utf-8")
