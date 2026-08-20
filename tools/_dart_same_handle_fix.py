from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one match, found {count}: {old!r}")
    target.write_text(text.replace(old, new), encoding="utf-8")


replace_once(
    "src/windows_local_mcp/approval.py",
    '''    try:\n        payload = json.loads(checked_config.read_text(encoding="utf-8"))\n    except (UnicodeDecodeError, json.JSONDecodeError) as error:\n''',
    '''    try:\n        config_bytes = read_verified_bytes(\n            checked_config, settings.approval_manifest_max_bytes\n        )\n        payload = json.loads(config_bytes.decode("utf-8"))\n    except (UnicodeDecodeError, json.JSONDecodeError) as error:\n''',
)

path = Path("tests/test_same_handle_reads.py")
text = path.read_text(encoding="utf-8")
needle = '''    records = approval._copy_tree_bounded(\n        source=root,\n        destination=staged,\n        settings=server.runtime.settings,\n        workspace=server.runtime.workspace,\n    )\n    assert records\n'''
replacement = '''    records = approval._copy_tree_bounded(\n        source=root,\n        destination=staged,\n        settings=server.runtime.settings,\n        workspace=server.runtime.workspace,\n    )\n    assert records\n\n    dart_tool = root / ".dart_tool"\n    dart_tool.mkdir()\n    package_config = dart_tool / "package_config.json"\n    package_config.write_text('{"packages": []}', encoding="utf-8")\n    guarded.add(package_config.resolve(strict=False))\n    staged_cwd = tmp_path / "dart-staged-cwd"\n    (staged_cwd / ".dart_tool").mkdir(parents=True)\n    staged_config = staged_cwd / ".dart_tool" / "package_config.json"\n    staged_config.write_text('{"packages": []}', encoding="utf-8")\n    dependency_stage = tmp_path / "dart-dependency-stage"\n    dependency_stage.mkdir()\n    dart_records = [approval._file_record(staged_config)]\n    dart_records[0].update(\n        {"source_path": str(package_config), "staged_path": str(staged_config)}\n    )\n    assert approval._stage_dart_package_dependencies(\n        source_cwd=root,\n        staged_cwd=staged_cwd,\n        stage_root=dependency_stage,\n        settings=server.runtime.settings,\n        workspace=server.runtime.workspace,\n        records=dart_records,\n    ) == []\n'''
if text.count(needle) != 1:
    raise RuntimeError("same-handle sink test insertion point not found exactly once")
path.write_text(text.replace(needle, replacement), encoding="utf-8")

print("Dart package_config workspace read migrated to same HANDLE")
