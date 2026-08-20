from __future__ import annotations

from pathlib import Path

ROOT = Path.cwd()


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected one match in {path}, found {count}: {old[:100]!r}")
    write(path, text.replace(old, new, 1))


def replace_between(path: str, start: str, end: str, replacement: str) -> None:
    text = read(path)
    start_index = text.find(start)
    if start_index < 0:
        raise RuntimeError(f"start marker not found in {path}: {start!r}")
    end_index = text.find(end, start_index)
    if end_index < 0:
        raise RuntimeError(f"end marker not found in {path}: {end!r}")
    if text.find(start, start_index + 1) >= 0:
        raise RuntimeError(f"start marker is not unique in {path}: {start!r}")
    write(path, text[:start_index] + replacement + text[end_index:])


replace_once(
    "src/windows_local_mcp/paths.py",
    """                transactional_write_bytes(\n                    actual_target,\n                    data,\n                    expected_identity=expected_native,\n                    expected_sha256=expected_sha256,\n                )\n""",
    """                transactional_write_bytes(\n                    actual_target,\n                    data,\n                    expected_identity=expected_native,\n                    expected_size=(\n                        target_identity.size if target_identity is not None else None\n                    ),\n                    expected_sha256=expected_sha256,\n                )\n""",
)
replace_once(
    "src/windows_local_mcp/paths.py",
    """                transactional_delete(\n                    actual_target,\n                    expected_identity=(\n                        target_identity.windows_volume_serial,\n                        target_identity.windows_file_index,\n                    ),\n                    expected_sha256=expected_sha256,\n                )\n""",
    """                transactional_delete(\n                    actual_target,\n                    expected_identity=(\n                        target_identity.windows_volume_serial,\n                        target_identity.windows_file_index,\n                    ),\n                    expected_size=target_identity.size,\n                    expected_sha256=expected_sha256,\n                )\n""",
)

replace_once(
    "src/windows_local_mcp/config.py",
    "from .windows_system import physical_filesystem_path, windows_system_executable\n",
    "from .windows_system import physical_filesystem_path, windows_system_executable\n"
    "from .windows_transaction import probe_transactional_workspace_commit\n",
)
replace_once(
    "src/windows_local_mcp/config.py",
    """        if self.filesystem_enabled:\n            _probe_filesystem_semantics(self.workspace_root)\n""",
    """        if self.filesystem_enabled:\n            _probe_filesystem_semantics(self.workspace_root)\n            probe_transactional_workspace_commit(self.workspace_root)\n""",
)

server_helper = '''def _recover_single_file_after_failed_postwrite(\n    path: str,\n    *,\n    before: bytes,\n    expected_after_sha256: str,\n    existed_before: bool,\n) -> None:\n    """Restore one transaction-owned result without overwriting a later third-party change."""\n    target = runtime.workspace.resolve_for_write(path)\n    parent_identity = runtime.workspace.identity(target.parent)\n    target_identity = runtime.workspace.identity(target)\n    if parent_identity is None or target_identity is None:\n        raise RuntimeError("automatic recovery target disappeared")\n    live = target.read_bytes()\n    if sha256_bytes(live) != expected_after_sha256:\n        raise RuntimeError("automatic recovery refused to overwrite a concurrent target change")\n    if existed_before:\n        runtime.workspace.commit_bytes(\n            target,\n            before,\n            parent_identity=parent_identity,\n            target_identity=target_identity,\n            expected_sha256=expected_after_sha256,\n        )\n    else:\n        runtime.workspace.commit_delete(\n            target,\n            parent_identity=parent_identity,\n            target_identity=target_identity,\n            expected_sha256=expected_after_sha256,\n        )\n    restored_target = runtime.workspace.resolve_for_write(path)\n    restored_exists = restored_target.exists()\n    restored = restored_target.read_bytes() if restored_exists else b""\n    if restored_exists != existed_before or restored != before:\n        raise RuntimeError("automatic recovery verification failed")\n\n\n'''
replace_once(
    "src/windows_local_mcp/server.py",
    "\ndef _atomic_binary_mutation(\n",
    "\n" + server_helper + "def _atomic_binary_mutation(\n",
)
replace_once(
    "src/windows_local_mcp/server.py",
    '''            temp_path: Path | None = None\n            workspace_changed = False\n            try:\n                with tempfile.NamedTemporaryFile(\n                    mode="wb", delete=False, dir=target.parent, prefix=f".{target.name}.", suffix=".tmp"\n                ) as temp:\n                    temp.write(after)\n                    temp.flush()\n                    os.fsync(temp.fileno())\n                    temp_path = Path(temp.name)\n                runtime.workspace.revalidate_for_replace(\n                    target, parent_identity=parent_identity, target_identity=target_identity\n                )\n                current_exists = target.exists()\n                if current_exists != (target_identity is not None):\n                    raise RuntimeError("structured file changed concurrently before replacement")\n                if current_exists and sha256_bytes(target.read_bytes()) != before_sha:\n                    raise RuntimeError("source is stale or concurrently modified")\n                _verify_binary_source_bindings(source_bindings)\n                os.replace(temp_path, target)\n                temp_path = None\n                workspace_changed = True\n''',
    '''            workspace_changed = False\n            try:\n                _verify_binary_source_bindings(source_bindings)\n                runtime.workspace.commit_bytes(\n                    target,\n                    after,\n                    parent_identity=parent_identity,\n                    target_identity=target_identity,\n                    expected_sha256=before_sha if target_identity is not None else None,\n                )\n                workspace_changed = True\n''',
)
replace_once(
    "src/windows_local_mcp/server.py",
    '''                    try:\n                        live_exists = target.exists()\n                        live_bytes = target.read_bytes() if live_exists else b""\n                        if not live_exists or live_bytes != after:\n                            raise RuntimeError(\n                                "automatic recovery refused to overwrite a concurrent target change"\n                            )\n                        if target_identity is None:\n                            target.unlink(missing_ok=True)\n                        else:\n                            with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=target.parent) as recovery:\n                                recovery.write(before)\n                                recovery.flush()\n                                os.fsync(recovery.fileno())\n                                recovery_path = Path(recovery.name)\n                            os.replace(recovery_path, target)\n                        restored = target.read_bytes() if target.exists() else b""\n                        if restored != before or target.exists() != (target_identity is not None):\n                            raise RuntimeError("binary mutation recovery verification failed")\n''',
    '''                    try:\n                        _recover_single_file_after_failed_postwrite(\n                            path,\n                            before=before,\n                            expected_after_sha256=after_sha,\n                            existed_before=target_identity is not None,\n                        )\n''',
)
replace_once(
    "src/windows_local_mcp/server.py",
    '''            finally:\n                if temp_path is not None:\n                    temp_path.unlink(missing_ok=True)\n                if operation_id is not None:\n''',
    '''            finally:\n                if operation_id is not None:\n''',
)
replace_once(
    "src/windows_local_mcp/server.py",
    '''            temp_path: Path | None = None\n            workspace_changed = False\n            begin_single_file_write_transaction(\n                runtime.settings,\n                operation_id,\n                pre_workspace.manifest_path,\n                runtime.workspace.relative(target),\n                before_sha if target_identity is not None else None,\n                sha256_bytes(content_bytes),\n            )\n            try:\n                with tempfile.NamedTemporaryFile(\n                    mode="wb",\n                    delete=False,\n                    dir=target.parent,\n                    prefix=f".{target.name}.",\n                    suffix=".tmp",\n                ) as temp:\n                    temp.write(content_bytes)\n                    temp.flush()\n                    os.fsync(temp.fileno())\n                    temp_path = Path(temp.name)\n                runtime.workspace.revalidate_for_replace(\n                    target,\n                    parent_identity=parent_identity,\n                    target_identity=target_identity,\n                )\n                os.replace(temp_path, target)\n                temp_path = None\n                workspace_changed = True\n            except Exception as write_error:\n                if not workspace_changed:\n                    update_single_file_write_transaction(\n                        runtime.settings,\n                        operation_id,\n                        state="failed_recovered",\n                        error=write_error,\n                    )\n                raise\n            finally:\n                if temp_path is not None:\n                    temp_path.unlink(missing_ok=True)\n''',
    '''            workspace_changed = False\n            begin_single_file_write_transaction(\n                runtime.settings,\n                operation_id,\n                pre_workspace.manifest_path,\n                runtime.workspace.relative(target),\n                before_sha if target_identity is not None else None,\n                sha256_bytes(content_bytes),\n            )\n            try:\n                runtime.workspace.commit_bytes(\n                    target,\n                    content_bytes,\n                    parent_identity=parent_identity,\n                    target_identity=target_identity,\n                    expected_sha256=before_sha if target_identity is not None else None,\n                )\n                workspace_changed = True\n            except Exception as write_error:\n                if not workspace_changed:\n                    update_single_file_write_transaction(\n                        runtime.settings,\n                        operation_id,\n                        state="failed_recovered",\n                        error=write_error,\n                    )\n                raise\n''',
)
replace_once(
    "src/windows_local_mcp/server.py",
    '''                try:\n                    live_exists = target.exists()\n                    live_bytes = target.read_bytes() if live_exists else b""\n                    if not live_exists or live_bytes != content_bytes:\n                        raise RuntimeError(\n                            "automatic recovery refused to overwrite a concurrent target change"\n                        )\n                    if target_identity is None:\n                        target.unlink(missing_ok=True)\n                    else:\n                        recovery_temp: Path | None = None\n                        try:\n                            with tempfile.NamedTemporaryFile(\n                                mode="wb", delete=False, dir=target.parent\n                            ) as recovery:\n                                recovery.write(previous_bytes)\n                                recovery.flush()\n                                os.fsync(recovery.fileno())\n                                recovery_temp = Path(recovery.name)\n                            os.replace(recovery_temp, target)\n                            recovery_temp = None\n                        finally:\n                            if recovery_temp is not None:\n                                recovery_temp.unlink(missing_ok=True)\n                    recovered = target.read_bytes() if target.exists() else b""\n                    existed_before = target_identity is not None\n                    if recovered != previous_bytes or target.exists() != existed_before:\n                        raise RuntimeError("write recovery verification failed")\n''',
    '''                try:\n                    _recover_single_file_after_failed_postwrite(\n                        path,\n                        before=previous_bytes,\n                        expected_after_sha256=sha256_bytes(content_bytes),\n                        existed_before=target_identity is not None,\n                    )\n''',
)
replace_once(
    "src/windows_local_mcp/server.py",
    '''                        "filesystem_identity_lock_replace": {\n                            "status": "verified",\n                            "evidence": "startup filesystem identity/lock/replace probe",\n                        },\n''',
    '''                        "filesystem_identity_atomic_commit": {\n                            "status": "verified",\n                            "evidence": "startup identity/lock/TxF transactional-commit probe",\n                        },\n''',
)

workspace_apply = '''def _apply_manifest(\n    settings: Settings,\n    manifest_path: str,\n    *,\n    staged_root: Path | None = None,\n    only_paths: set[str] | None = None,\n    journal: dict[str, Any] | None = None,\n    journal_path: Path | None = None,\n    expected_hashes: dict[str, str] | None = None,\n) -> None:\n    manifest = _load_manifest(settings, manifest_path)\n    target_map = _entry_map(manifest)\n    scope_paths = _scope_paths(_manifest_scope(manifest))\n    current = _scan_current_hashes(settings, scope_paths)\n    if expected_hashes is not None and current != expected_hashes:\n        raise RuntimeError("workspace changed during restore staging")\n    changed = (\n        only_paths\n        if only_paths is not None\n        else set(current.keys()) | set(target_map.keys())\n    )\n    workspace = Workspace(settings)\n\n    for relative in sorted((set(current) - set(target_map)) & changed, reverse=True):\n        destination = workspace.resolve_for_write(relative)\n        _verify_destination_digest(destination, current.get(relative), relative)\n        parent_identity = workspace.identity(destination.parent)\n        target_identity = workspace.identity(destination)\n        if parent_identity is None or target_identity is None:\n            raise RuntimeError(f"restore delete target disappeared: {relative}")\n        expected = current.get(relative)\n        if expected is None:\n            raise RuntimeError(f"restore delete has no expected digest: {relative}")\n        workspace.commit_delete(\n            destination,\n            parent_identity=parent_identity,\n            target_identity=target_identity,\n            expected_sha256=expected,\n        )\n        _journal_applied(journal, journal_path, relative)\n\n    for relative in sorted(set(target_map) & changed):\n        parent_relative = str(PurePosixPath(relative).parent)\n        parent_path = workspace.root / Path(parent_relative)\n        missing_directories: list[str] = []\n        current_parent = parent_path\n        while current_parent != workspace.root and not current_parent.exists():\n            missing_directories.append(\n                current_parent.relative_to(workspace.root).as_posix()\n            )\n            current_parent = current_parent.parent\n        if missing_directories and journal is not None and journal_path is not None:\n            created = {str(item) for item in journal.get("created_directories", [])}\n            created.update(missing_directories)\n            journal["created_directories"] = sorted(created)\n            _write_json_atomic(journal_path, journal)\n        workspace.ensure_directory_for_write(parent_relative)\n        destination = workspace.resolve_for_write(relative)\n        entry = target_map[relative]\n        source = (\n            staged_root / Path(relative)\n            if staged_root is not None and (staged_root / Path(relative)).exists()\n            else _entry_source(settings, Path(manifest_path), entry)\n        )\n        data = source.read_bytes()\n        if sha256_bytes(data) != entry["sha256"]:\n            raise RuntimeError(f"restore content changed after preflight: {relative}")\n        parent_identity = workspace.identity(destination.parent)\n        target_identity = workspace.identity(destination)\n        if parent_identity is None:\n            raise RuntimeError(f"restore parent disappeared: {relative}")\n        expected = current.get(relative)\n        _verify_destination_digest(destination, expected, relative)\n        workspace.commit_bytes(\n            destination,\n            data,\n            parent_identity=parent_identity,\n            target_identity=target_identity,\n            expected_sha256=expected if target_identity is not None else None,\n        )\n        _journal_applied(journal, journal_path, relative)\n'''
replace_between(
    "src/windows_local_mcp/workspace_history.py",
    "def _apply_manifest(\n",
    "\n\ndef _remove_created_directories",
    workspace_apply,
)

write("src/windows_local_mcp/__init__.py", '__version__ = "0.6.0"\n')
shim = ROOT / "src/windows_local_mcp/workspace_atomic.py"
if not shim.exists():
    raise RuntimeError("expected temporary workspace_atomic.py shim")
shim.unlink()

write(
    "tests/test_workspace_transaction_commit.py",
    '''from __future__ import annotations\n\nimport hashlib\nimport os\nimport subprocess\nimport sys\nfrom pathlib import Path\n\nimport pytest\n\nfrom windows_local_mcp.windows_transaction import (\n    probe_transactional_workspace_commit,\n    transactional_write_bytes,\n    windows_file_identity,\n)\n\npytestmark = pytest.mark.skipif(\n    os.name != "nt", reason="Transactional NTFS is the Windows workspace commit boundary"\n)\n\n\ndef test_txf_probe_round_trips_workspace_commits(tmp_path: Path) -> None:\n    probe_transactional_workspace_commit(tmp_path)\n    assert not list(tmp_path.glob(".wlmcp-txf-probe-*"))\n\n\ndef test_txf_rejects_stale_digest_without_mutating_target(tmp_path: Path) -> None:\n    target = tmp_path / "target.txt"\n    target.write_bytes(b"before")\n    identity = windows_file_identity(target)\n\n    with pytest.raises(RuntimeError, match="content changed"):\n        transactional_write_bytes(\n            target,\n            b"intended",\n            expected_identity=(identity.volume_serial, identity.file_index),\n            expected_size=identity.size,\n            expected_sha256="0" * 64,\n        )\n\n    assert target.read_bytes() == b"before"\n\n\ndef test_txf_blocks_external_replace_between_validation_and_commit(tmp_path: Path) -> None:\n    target = tmp_path / "target.txt"\n    target.write_bytes(b"before")\n    replacement = tmp_path / "replacement.txt"\n    replacement.write_bytes(b"attacker")\n    identity = windows_file_identity(target)\n    attempts: list[subprocess.CompletedProcess[str]] = []\n\n    def attack_before_commit() -> None:\n        script = "import os,sys; os.replace(sys.argv[1], sys.argv[2])"\n        attempt = subprocess.run(\n            [sys.executable, "-c", script, str(replacement), str(target)],\n            capture_output=True,\n            text=True,\n            timeout=10,\n            check=False,\n        )\n        attempts.append(attempt)\n        assert attempt.returncode != 0, "external replacement unexpectedly succeeded inside TxF"\n\n    transactional_write_bytes(\n        target,\n        b"intended",\n        expected_identity=(identity.volume_serial, identity.file_index),\n        expected_size=identity.size,\n        expected_sha256=hashlib.sha256(b"before").hexdigest(),\n        _before_commit=attack_before_commit,\n    )\n\n    assert len(attempts) == 1\n    assert target.read_bytes() == b"intended"\n    assert replacement.read_bytes() == b"attacker"\n''',
)

readme = read("README.md")
marker = "## Windows workspace transactional commit requirement"
if marker not in readme:
    readme += '''\n\n## Windows workspace transactional commit requirement\n\nBroker workspace mutation, rollback, and Undo require usable Transactional NTFS (TxF) on the configured local workspace volume. Startup probes the actual workspace for existing-file write, create, and delete transaction semantics. If TxF is unavailable (for example on unsupported remote/ReFS-style storage), the filesystem write route fails closed instead of falling back to a validation-then-`os.replace()` sequence. Read-only capabilities remain conceptually separate from this commit guarantee.\n'''
    write("README.md", readme)

verification = read("VERIFICATION.md")
verification_marker = "## Workspace TxF commit-race verification"
if verification_marker not in verification:
    verification += '''\n\n## Workspace TxF commit-race verification\n\n`tests/test_workspace_transaction_commit.py` exercises the Windows transaction boundary directly. The race test opens a transacted writer, performs the expected identity/size/SHA-256 validation and intended write, then deliberately launches a separate non-transacted process that attempts `os.replace()` before `CommitTransaction`. The external replacement must fail and the intended transaction must commit. Startup also runs the TxF existing-write/create/delete probe against the configured workspace volume and fails closed when the required semantics are unavailable.\n'''
    write("VERIFICATION.md", verification)

print("atomic workspace commit patch prepared")
