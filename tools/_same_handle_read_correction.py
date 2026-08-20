from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one match, found {count}: {old[:100]!r}")
    target.write_text(text.replace(old, new), encoding="utf-8")


PATHS = "src/windows_local_mcp/paths.py"
SERVER = "src/windows_local_mcp/server.py"
HISTORY = "src/windows_local_mcp/workspace_history.py"
SANDBOX_TESTS = "tests/test_sandbox_architecture.py"
SAME_HANDLE_TESTS = "tests/test_same_handle_reads.py"

# A write-target lease must keep path identity stable without holding GENERIC_READ for the
# entire transform. The actual preimage read gets its own short-lived validated readable HANDLE.
replace_once(
    PATHS,
    '''            allow_directory=False,\n            allow_hardlinks=False,\n            write_intent=True,\n            final_read_data=True,\n        )\n''',
    '''            allow_directory=False,\n            allow_hardlinks=False,\n            write_intent=True,\n        )\n''',
)

replace_once(
    PATHS,
    '''    return data\n\n\ndef _windows_component_handles(\n''',
    '''    return data\n\n\ndef read_verified_path_bytes(path: Path, max_bytes: int) -> bytes:\n    """Validate and read one path through the same short-lived Windows file HANDLE."""\n    verified = hold_verified_path(\n        Path(str(path)),\n        allow_directory=False,\n        allow_hardlinks=False,\n        readable=True,\n    )\n    try:\n        return read_verified_bytes(verified, max_bytes)\n    finally:\n        release_verified_hold(verified)\n\n\ndef _windows_component_handles(\n''',
)

replace_once(
    PATHS,
    '''    On Windows, every path component is opened with reparse-point semantics and retained\n    without FILE_SHARE_DELETE. The final regular file also denies FILE_SHARE_WRITE. This\n    prevents a same-user process from replacing a validated path, any parent directory, or\n    the file itself before a caller later opens the returned path.\n''',
    '''    On Windows, every path component is opened with reparse-point semantics and retained\n    without FILE_SHARE_DELETE. A readable final handle is consumed directly by ReadFile; a\n    path-only lease is retained for external-process bindings and write-intent identity checks.\n    This prevents namespace replacement while avoiding pathname re-open as the Broker read\n    security boundary.\n''',
)

replace_once(
    SERVER,
    "import hashlib\n",
    "",
)
replace_once(
    SERVER,
    '''from .paths import PathIdentity, Workspace, read_verified_bytes, release_verified_hold\n''',
    '''from .paths import (\n    PathIdentity,\n    Workspace,\n    read_verified_bytes,\n    read_verified_path_bytes,\n    release_verified_hold,\n)\n''',
)

# Distinct source bindings need a path identity lease across the mutation, but not a readable
# HANDLE that would suppress the very concurrent-change signal we must detect.
replace_once(
    SERVER,
    '''        if source != target:\n            source = runtime.workspace.resolve_existing(source_path, allow_directory=False)\n        bound_sources.append(source)\n''',
    '''        if source != target:\n            source = runtime.workspace.resolve_existing(\n                source_path, allow_directory=False, readable=False\n            )\n        bound_sources.append(source)\n''',
)

# Short-lived same-HANDLE reads for write targets preserve optimistic concurrency: after the
# read HANDLE closes, a third party may write, and TxF CAS rejects that stale preimage at commit.
for old, new in [
    (
        "read_verified_bytes(current, len(after))",
        "read_verified_path_bytes(current, len(after))",
    ),
    (
        "read_verified_bytes(\n                    target, runtime.settings.max_structured_file_bytes\n                )",
        "read_verified_path_bytes(\n                    target, runtime.settings.max_structured_file_bytes\n                )",
    ),
    (
        "read_verified_bytes(target, runtime.settings.max_structured_file_bytes)",
        "read_verified_path_bytes(target, runtime.settings.max_structured_file_bytes)",
    ),
    (
        "read_verified_bytes(\n                target, runtime.settings.max_structured_file_bytes\n            )",
        "read_verified_path_bytes(\n                target, runtime.settings.max_structured_file_bytes\n            )",
    ),
]:
    text = Path(SERVER).read_text(encoding="utf-8")
    if old in text:
        Path(SERVER).write_text(text.replace(old, new), encoding="utf-8")

replace_once(
    SERVER,
    '''            previous_bytes = (\n                read_verified_bytes(\n                    target,\n                    max(\n                        runtime.settings.max_text_file_bytes,\n                        runtime.settings.max_backup_bytes,\n                    ),\n                )\n                if target.exists()\n                else b""\n            )\n''',
    '''            previous_bytes = (\n                read_verified_path_bytes(\n                    target,\n                    max(\n                        runtime.settings.max_text_file_bytes,\n                        runtime.settings.max_backup_bytes,\n                    ),\n                )\n                if target.exists()\n                else b""\n            )\n''',
)

replace_once(
    SERVER,
    '''            if target.exists():\n                backup_dir = runtime.settings.data_dir / "backups" / operation_id\n                backup_dir.mkdir(parents=True)\n                backup_file = backup_dir / target.name\n                shutil.copy2(target, backup_file)\n                backup_path = str(backup_file)\n''',
    '''            if target.exists():\n                backup_dir = runtime.settings.data_dir / "backups" / operation_id\n                backup_dir.mkdir(parents=True)\n                backup_file = backup_dir / target.name\n                backup_file.write_bytes(previous_bytes)\n                backup_path = str(backup_file)\n''',
)

# get_image no longer needs a second size variable after bounded same-HANDLE read.
replace_once(
    SERVER,
    '''        data = read_verified_bytes(image_path, runtime.settings.max_image_bytes)\n        size = len(data)\n        _log_simple(\n''',
    '''        data = read_verified_bytes(image_path, runtime.settings.max_image_bytes)\n        _log_simple(\n''',
)

# Restore digest checks receive a write-intent path lease, so open a short-lived validated
# readable handle for the exact object instead of expecting the write lease itself to be readable.
replace_once(
    HISTORY,
    "from .paths import Workspace, read_verified_bytes\n",
    "from .paths import Workspace, read_verified_bytes, read_verified_path_bytes\n",
)
replace_once(
    HISTORY,
    '''        if not path.is_file() or sha256_bytes(read_verified_bytes(path, size)) != expected:\n''',
    '''        if not path.is_file() or sha256_bytes(read_verified_path_bytes(path, size)) != expected:\n''',
)

# The old test injected failure at Path.read_bytes. After same-HANDLE migration, inject the
# equivalent failure at the new security primitive so fail-closed behavior remains tested.
replace_once(
    SANDBOX_TESTS,
    '''    original = Path.read_bytes\n\n    def fail_target(path: Path) -> bytes:\n        if path == target:\n            raise PermissionError("sharing violation")\n        return original(path)\n\n    monkeypatch.setattr(Path, "read_bytes", fail_target)\n''',
    '''    from windows_local_mcp import workspace_history\n\n    original = workspace_history.read_verified_bytes\n\n    def fail_target(path: Path, max_bytes: int) -> bytes:\n        if Path(str(path)) == target:\n            raise PermissionError("sharing violation")\n        return original(path, max_bytes)\n\n    monkeypatch.setattr(workspace_history, "read_verified_bytes", fail_target)\n''',
)

replace_once(
    SAME_HANDLE_TESTS,
    "from windows_local_mcp.util import sha256_bytes\n",
    "",
)

print("same-HANDLE concurrency and regression corrections applied")
