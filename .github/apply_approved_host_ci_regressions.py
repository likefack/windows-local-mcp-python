from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    with (ROOT / path).open("w", encoding="utf-8", newline="\n") as output:
        output.write(text)


def replace_once(path: str, old: str, new: str, label: str) -> None:
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: {label}: expected one replacement target, found {count}")
    write(path, text.replace(old, new, 1))


# 1. Downstream Approved Host integration: keep the real isolated worker, but replace only
# the production runtime dependency-state capture inside that worker. No production bypass
# switch or ambient environment variable is introduced.
replace_once(
    "tests/conftest.py",
    '''        "file_count": 0,\n        "directory_count": 0,\n''',
    '''        "file_count": 0,\n        "bytes": 0,\n        "directory_count": 0,\n''',
    "trusted runtime evidence bytes",
)
replace_once(
    "tests/conftest.py",
    '''\n\n@pytest.fixture(autouse=True)\ndef _isolate_downstream_approved_host_integration(\n''',
    '''\n\ndef _isolated_worker_argv_with_trusted_runtime_state(\n    settings: Any,\n    *,\n    operation_id: str,\n    context_path: Path,\n    context_sha256: str,\n) -> list[str]:\n    from windows_local_mcp.control_plane import isolated_worker_argv\n\n    argv = isolated_worker_argv(\n        settings,\n        operation_id=operation_id,\n        context_path=context_path,\n        context_sha256=context_sha256,\n    )\n    command_index = argv.index("-c") + 1\n    bootstrap = argv[command_index]\n    marker = "runpy.run_module('windows_local_mcp.worker',run_name='__main__')"\n    if marker not in bootstrap:\n        raise RuntimeError("isolated worker bootstrap shape changed")\n    runtime_patch = (\n        "import windows_local_mcp.control_plane_guard as _guard;"\n        f"_guard.capture_runtime_dependency_state=lambda **_kwargs:{_trusted_runtime_evidence()!r};"\n    )\n    argv[command_index] = bootstrap.replace(marker, runtime_patch + marker, 1)\n    return argv\n\n\n@pytest.fixture(autouse=True)\ndef _isolate_downstream_approved_host_integration(\n''',
    "isolated worker runtime-state fixture helper",
)
replace_once(
    "tests/conftest.py",
    '''    monkeypatch.setattr(\n        "windows_local_mcp.executor.assert_approved_host_runtime_immutable",\n        _trusted_runtime_evidence,\n    )\n''',
    '''    monkeypatch.setattr(\n        "windows_local_mcp.executor.assert_approved_host_runtime_immutable",\n        _trusted_runtime_evidence,\n    )\n    monkeypatch.setattr(\n        "windows_local_mcp.executor.isolated_worker_argv",\n        _isolated_worker_argv_with_trusted_runtime_state,\n    )\n''',
    "isolated worker runtime-state fixture install",
)

# 2. Guard regression: a trusted AuditStore mutation is supposed to advance the mirror-backed
# expected state. Preserve an immutable copy to prove request_hash still changes the captured
# state, while the active guard follows the trusted mutation.
replace_once(
    "tests/test_broker_architecture.py",
    '''import json\nimport os\n''',
    '''import copy\nimport json\nimport os\n''',
    "copy import",
)
replace_once(
    "tests/test_broker_architecture.py",
    '''def test_host_guard_binds_current_operation_approval_state(tmp_path: Path) -> None:\n    settings = settings_for(tmp_path)\n    audit = AuditStore(settings)\n    operation = audit.create_operation(\n        tool_name="host",\n        tier="approved_host",\n        status="running",\n        cwd=str(settings.workspace_root),\n        request={"normalized_command": {"program_key": "python"}},\n        request_hash="a" * 64,\n        approval_status="approved",\n    )\n    before = capture_critical_state(settings, operation)\n\n    audit.update_operation(operation, request_hash="b" * 64)\n\n    assert capture_critical_state(settings, operation) != before\n''',
    '''def test_host_guard_tracks_trusted_operation_approval_state(tmp_path: Path) -> None:\n    settings = settings_for(tmp_path)\n    audit = AuditStore(settings)\n    operation = audit.create_operation(\n        tool_name="host",\n        tier="approved_host",\n        status="running",\n        cwd=str(settings.workspace_root),\n        request={"normalized_command": {"program_key": "python"}},\n        request_hash="a" * 64,\n        approval_status="approved",\n    )\n    before = capture_critical_state(settings, operation)\n    original = copy.deepcopy(before)\n\n    audit.update_operation(operation, request_hash="b" * 64)\n    after = capture_critical_state(settings, operation)\n\n    assert after == before\n    assert after != original\n''',
    "trusted audit guard regression",
)

# 3. Runtime dependency capture: honor an operation deadline during tree/namespace/file/ACL
# traversal instead of only checking after the full closure has been hashed.
replace_once(
    "src/windows_local_mcp/runtime_trust.py",
    '''import sys\nimport sysconfig\n''',
    '''import sys\nimport sysconfig\nimport time\n''',
    "runtime trust time import",
)
replace_once(
    "src/windows_local_mcp/runtime_trust.py",
    '''class RuntimeTrustInventory:\n    trees: tuple[RuntimeTree, ...]\n    namespace_roots: tuple[Path, ...]\n    security_paths: tuple[Path, ...]\n    files: tuple[Path, ...]\n    distributions: tuple[tuple[str, str], ...]\n\n\ndef _canonical_distribution_name''',
    '''class RuntimeTrustInventory:\n    trees: tuple[RuntimeTree, ...]\n    namespace_roots: tuple[Path, ...]\n    security_paths: tuple[Path, ...]\n    files: tuple[Path, ...]\n    distributions: tuple[tuple[str, str], ...]\n\n\ndef _check_deadline(deadline: float | None) -> None:\n    if deadline is not None and time.monotonic() >= deadline:\n        raise TimeoutError("trusted runtime dependency capture exceeded operation deadline")\n\n\ndef _canonical_distribution_name''',
    "runtime trust deadline helper",
)
replace_once(
    "src/windows_local_mcp/runtime_trust.py",
    '''def _tree_entries(tree: RuntimeTree) -> tuple[list[Path], list[Path]]:\n    root = _resolved_existing(tree.root)\n''',
    '''def _tree_entries(\n    tree: RuntimeTree, *, deadline: float | None = None\n) -> tuple[list[Path], list[Path]]:\n    _check_deadline(deadline)\n    root = _resolved_existing(tree.root)\n''',
    "tree deadline signature",
)
replace_once(
    "src/windows_local_mcp/runtime_trust.py",
    '''    for current, directories, names in os.walk(root, followlinks=False):\n        current_path = Path(current)\n        retained: list[str] = []\n        for name in directories:\n            candidate = current_path / name\n''',
    '''    for current, directories, names in os.walk(root, followlinks=False):\n        _check_deadline(deadline)\n        current_path = Path(current)\n        retained: list[str] = []\n        for name in directories:\n            _check_deadline(deadline)\n            candidate = current_path / name\n''',
    "tree directory deadline checks",
)
replace_once(
    "src/windows_local_mcp/runtime_trust.py",
    '''        directories[:] = retained\n        for name in names:\n            candidate = current_path / name\n''',
    '''        directories[:] = retained\n        for name in names:\n            _check_deadline(deadline)\n            candidate = current_path / name\n''',
    "tree file deadline checks",
)
replace_once(
    "src/windows_local_mcp/runtime_trust.py",
    '''def _namespace_records(roots: tuple[Path, ...]) -> list[dict[str, Any]]:\n    records: list[dict[str, Any]] = []\n    for root in roots:\n        resolved = _resolved_existing(root)\n''',
    '''def _namespace_records(\n    roots: tuple[Path, ...], *, deadline: float | None = None\n) -> list[dict[str, Any]]:\n    records: list[dict[str, Any]] = []\n    for root in roots:\n        _check_deadline(deadline)\n        resolved = _resolved_existing(root)\n''',
    "namespace deadline signature",
)
replace_once(
    "src/windows_local_mcp/runtime_trust.py",
    '''        entries: list[dict[str, Any]] = []\n        for child in sorted(resolved.iterdir(), key=lambda item: item.name.casefold()):\n            kind = _namespace_entry_kind(child)\n''',
    '''        entries: list[dict[str, Any]] = []\n        for child in sorted(resolved.iterdir(), key=lambda item: item.name.casefold()):\n            _check_deadline(deadline)\n            kind = _namespace_entry_kind(child)\n''',
    "namespace entry deadline checks",
)
replace_once(
    "src/windows_local_mcp/runtime_trust.py",
    '''def capture_runtime_dependency_state(\n    *,\n    max_files: int,\n    max_bytes: int,\n    inventory: RuntimeTrustInventory | None = None,\n) -> dict[str, Any]:\n    inventory = inventory or build_runtime_trust_inventory()\n''',
    '''def capture_runtime_dependency_state(\n    *,\n    max_files: int,\n    max_bytes: int,\n    inventory: RuntimeTrustInventory | None = None,\n    deadline: float | None = None,\n) -> dict[str, Any]:\n    _check_deadline(deadline)\n    inventory = inventory or build_runtime_trust_inventory()\n    _check_deadline(deadline)\n''',
    "runtime capture deadline signature",
)
replace_once(
    "src/windows_local_mcp/runtime_trust.py",
    '''    for tree in inventory.trees:\n        tree_files, tree_directories = _tree_entries(tree)\n''',
    '''    for tree in inventory.trees:\n        _check_deadline(deadline)\n        tree_files, tree_directories = _tree_entries(tree, deadline=deadline)\n''',
    "runtime tree deadline propagation",
)
replace_once(
    "src/windows_local_mcp/runtime_trust.py",
    '''    for path in sorted(candidates, key=lambda item: os.path.normcase(str(item))):\n        resolved = _resolved_existing(path)\n''',
    '''    for path in sorted(candidates, key=lambda item: os.path.normcase(str(item))):\n        _check_deadline(deadline)\n        resolved = _resolved_existing(path)\n''',
    "runtime file deadline checks",
)
replace_once(
    "src/windows_local_mcp/runtime_trust.py",
    '''    for directory in sorted(\n        directories, key=lambda item: os.path.normcase(str(item))\n    ):\n        details = directory.stat()\n''',
    '''    for directory in sorted(\n        directories, key=lambda item: os.path.normcase(str(item))\n    ):\n        _check_deadline(deadline)\n        details = directory.stat()\n''',
    "runtime directory deadline checks",
)
replace_once(
    "src/windows_local_mcp/runtime_trust.py",
    '''    security_records: list[dict[str, Any]] = []\n    for path in inventory.security_paths:\n        resolved = _resolved_existing(path)\n''',
    '''    security_records: list[dict[str, Any]] = []\n    for path in inventory.security_paths:\n        _check_deadline(deadline)\n        resolved = _resolved_existing(path)\n''',
    "runtime security-path deadline checks",
)
replace_once(
    "src/windows_local_mcp/runtime_trust.py",
    '''    namespace = _namespace_records(inventory.namespace_roots)\n''',
    '''    _check_deadline(deadline)\n    namespace = _namespace_records(inventory.namespace_roots, deadline=deadline)\n    _check_deadline(deadline)\n''',
    "runtime namespace deadline propagation",
)

# 4. Control-plane preflight: pass the same operation deadline into runtime capture and bound
# the expensive icacls startup/ACL probes by the remaining operation time.
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''import tempfile\nimport threading\n''',
    '''import tempfile\nimport threading\nimport time\n''',
    "control-plane time import",
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''def _tamper_marker(settings: Settings) -> Path:\n''',
    '''def _check_deadline(deadline: float | None) -> None:\n    if deadline is not None and time.monotonic() >= deadline:\n        raise TimeoutError("Approved Host control-plane preflight exceeded operation deadline")\n\n\ndef _deadline_timeout(deadline: float | None, maximum: float) -> float:\n    if deadline is None:\n        return maximum\n    remaining = deadline - time.monotonic()\n    if remaining <= 0:\n        raise TimeoutError("Approved Host control-plane preflight exceeded operation deadline")\n    return max(0.001, min(maximum, remaining))\n\n\ndef _tamper_marker(settings: Settings) -> Path:\n''',
    "control-plane deadline helpers",
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''def _startup_path_acl_digest(path: Path) -> str | None:\n    if os.name != "nt":\n        return None\n    completed = subprocess.run(\n        [windows_system_executable("icacls.exe"), str(path), "/C"],\n        capture_output=True,\n        timeout=10,\n        check=False,\n        shell=False,\n    )\n''',
    '''def _startup_path_acl_digest(\n    path: Path, *, deadline: float | None = None\n) -> str | None:\n    if os.name != "nt":\n        return None\n    _check_deadline(deadline)\n    try:\n        completed = subprocess.run(\n            [windows_system_executable("icacls.exe"), str(path), "/C"],\n            capture_output=True,\n            timeout=_deadline_timeout(deadline, 10),\n            check=False,\n            shell=False,\n        )\n    except subprocess.TimeoutExpired as error:\n        raise TimeoutError(\n            "Approved Host control-plane preflight exceeded operation deadline"\n        ) from error\n''',
    "startup ACL deadline",
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''def _capture_runtime_startup_state(paths: list[Path] | None = None) -> dict[str, Any]:\n    records: list[dict[str, Any]] = []\n    for candidate in paths or _runtime_startup_candidate_paths():\n        absolute = candidate.absolute()\n''',
    '''def _capture_runtime_startup_state(\n    paths: list[Path] | None = None, *, deadline: float | None = None\n) -> dict[str, Any]:\n    records: list[dict[str, Any]] = []\n    for candidate in paths or _runtime_startup_candidate_paths():\n        _check_deadline(deadline)\n        absolute = candidate.absolute()\n''',
    "startup-state deadline signature",
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''                    "acl_sha256": _startup_path_acl_digest(resolved),\n''',
    '''                    "acl_sha256": _startup_path_acl_digest(\n                        resolved, deadline=deadline\n                    ),\n''',
    "startup file ACL deadline propagation",
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''                    "acl_sha256": _startup_path_acl_digest(resolved),\n''',
    '''                    "acl_sha256": _startup_path_acl_digest(\n                        resolved, deadline=deadline\n                    ),\n''',
    "startup directory ACL deadline propagation",
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''def capture_critical_state(settings: Settings, operation_id: str) -> dict[str, Any]:\n    """Capture state that an Approved Host child is never allowed to mutate."""\n    database_identity = _database_identity(settings.data_dir / "audit.db")\n''',
    '''def capture_critical_state(\n    settings: Settings, operation_id: str, *, deadline: float | None = None\n) -> dict[str, Any]:\n    """Capture state that an Approved Host child is never allowed to mutate."""\n    _check_deadline(deadline)\n    database_identity = _database_identity(settings.data_dir / "audit.db")\n''',
    "critical-state deadline signature",
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''    for root in roots:\n        if not root.exists():\n''',
    '''    for root in roots:\n        _check_deadline(deadline)\n        if not root.exists():\n''',
    "critical root deadline checks",
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''            for current, directories, files in os.walk(root, followlinks=False):\n                current_path = Path(current)\n''',
    '''            for current, directories, files in os.walk(root, followlinks=False):\n                _check_deadline(deadline)\n                current_path = Path(current)\n''',
    "critical walk deadline checks",
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''        for path in sorted(candidates, key=lambda item: str(item).casefold()):\n            if path == _tamper_marker(settings):\n''',
    '''        for path in sorted(candidates, key=lambda item: str(item).casefold()):\n            _check_deadline(deadline)\n            if path == _tamper_marker(settings):\n''',
    "critical file deadline checks",
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''        capture_runtime_dependency_state(\n            max_files=settings.approval_manifest_max_files,\n            max_bytes=settings.approval_manifest_max_bytes,\n        )\n''',
    '''        capture_runtime_dependency_state(\n            max_files=settings.approval_manifest_max_files,\n            max_bytes=settings.approval_manifest_max_bytes,\n            deadline=deadline,\n        )\n''',
    "runtime deadline propagation into control-plane capture",
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''    runtime_startup_state = _capture_runtime_startup_state() if os.name == "nt" else None\n    audit_snapshot, audit_bytes = _audit_state_snapshot(settings)\n    acl_digest, acl_bytes = _acl_state_digest(settings, roots)\n''',
    '''    runtime_startup_state = (\n        _capture_runtime_startup_state(deadline=deadline) if os.name == "nt" else None\n    )\n    _check_deadline(deadline)\n    audit_snapshot, audit_bytes = _audit_state_snapshot(settings, deadline=deadline)\n    acl_digest, acl_bytes = _acl_state_digest(settings, roots, deadline=deadline)\n''',
    "critical expensive-state deadline propagation",
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''    mirror = _build_audit_mirror(settings)\n''',
    '''    _check_deadline(deadline)\n    mirror = _build_audit_mirror(settings, deadline=deadline)\n''',
    "audit mirror deadline propagation",
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''def _audit_state_snapshot(settings: Settings) -> tuple[dict[str, Any], int]:\n    database = settings.data_dir / "audit.db"\n    if not database.is_file():\n        raise RuntimeError("audit database disappeared before Approved Host execution")\n    connection = _ORIGINAL_SQLITE_CONNECT(f"file:{database}?mode=ro", uri=True, timeout=10)\n''',
    '''def _audit_state_snapshot(\n    settings: Settings, *, deadline: float | None = None\n) -> tuple[dict[str, Any], int]:\n    _check_deadline(deadline)\n    database = settings.data_dir / "audit.db"\n    if not database.is_file():\n        raise RuntimeError("audit database disappeared before Approved Host execution")\n    connection = _ORIGINAL_SQLITE_CONNECT(\n        f"file:{database}?mode=ro",\n        uri=True,\n        timeout=_deadline_timeout(deadline, 10),\n    )\n''',
    "audit snapshot deadline",
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''def _build_audit_mirror(settings: Settings) -> sqlite3.Connection:\n    database = settings.data_dir / "audit.db"\n    source = _ORIGINAL_SQLITE_CONNECT(f"file:{database}?mode=ro", uri=True, timeout=10)\n''',
    '''def _build_audit_mirror(\n    settings: Settings, *, deadline: float | None = None\n) -> sqlite3.Connection:\n    _check_deadline(deadline)\n    database = settings.data_dir / "audit.db"\n    source = _ORIGINAL_SQLITE_CONNECT(\n        f"file:{database}?mode=ro",\n        uri=True,\n        timeout=_deadline_timeout(deadline, 10),\n    )\n''',
    "audit mirror deadline",
)
replace_once(
    "src/windows_local_mcp/control_plane_guard.py",
    '''def _acl_state_digest(settings: Settings, roots: list[Path]) -> tuple[str | None, int]:\n    if os.name != "nt":\n        return None, 0\n    chunks: list[bytes] = []\n    total = 0\n    for root in roots:\n        if not root.exists():\n            continue\n        completed = subprocess.run(\n            [windows_system_executable("icacls.exe"), str(root), "/T", "/C"],\n            capture_output=True,\n            timeout=30,\n            check=False,\n            shell=False,\n        )\n''',
    '''def _acl_state_digest(\n    settings: Settings, roots: list[Path], *, deadline: float | None = None\n) -> tuple[str | None, int]:\n    if os.name != "nt":\n        return None, 0\n    chunks: list[bytes] = []\n    total = 0\n    for root in roots:\n        _check_deadline(deadline)\n        if not root.exists():\n            continue\n        try:\n            completed = subprocess.run(\n                [windows_system_executable("icacls.exe"), str(root), "/T", "/C"],\n                capture_output=True,\n                timeout=_deadline_timeout(deadline, 30),\n                check=False,\n                shell=False,\n            )\n        except subprocess.TimeoutExpired as error:\n            raise TimeoutError(\n                "Approved Host control-plane preflight exceeded operation deadline"\n            ) from error\n''',
    "control-plane ACL deadline",
)

# 5. Worker maps a preflight deadline expiry to terminal timed_out instead of leaving an
# operation running until the Executor foreground timeout.
replace_once(
    "src/windows_local_mcp/worker.py",
    '''            host_control_state = capture_critical_state(settings, operation_id)\n            audit.add_event(\n''',
    '''            host_control_state = capture_critical_state(\n                settings, operation_id, deadline=deadline\n            )\n            audit.add_event(\n''',
    "worker control-plane deadline propagation",
)
replace_once(
    "src/windows_local_mcp/worker.py",
    '''        except Exception as guard_error:  # noqa: BLE001 - host must not launch unguarded\n            audit.transition_operation(\n''',
    '''        except TimeoutError as guard_error:\n            audit.transition_operation(\n                operation_id,\n                from_statuses={"running"},\n                status="timed_out",\n                finished_at=utc_now_iso(),\n                error=f"Approved Host control-plane preflight exceeded operation deadline: {guard_error}",\n            )\n            audit.add_event(\n                operation_id,\n                "operation_deadline_exceeded",\n                {"error": str(guard_error)[:1000], "phase": "approved_host_preflight"},\n            )\n            if workspace_lock is not None:\n                workspace_lock.__exit__(None, None, None)\n            if host_control_locks is not None:\n                host_control_locks.close()\n            return 1\n        except Exception as guard_error:  # noqa: BLE001 - host must not launch unguarded\n            audit.transition_operation(\n''',
    "worker preflight timeout mapping",
)

# 6. Deadline regression: prove capture aborts between runtime entries rather than finishing
# an already-expired closure.
replace_once(
    "tests/test_runtime_trust.py",
    '''from pathlib import Path\n\nfrom windows_local_mcp.runtime_trust import (\n''',
    '''import time\nfrom pathlib import Path\n\nimport pytest\n\nimport windows_local_mcp.runtime_trust as runtime_trust\nfrom windows_local_mcp.runtime_trust import (\n''',
    "runtime trust deadline test imports",
)
replace_once(
    "tests/test_runtime_trust.py",
    '''\n\ndef test_runtime_generation_identity_binds_source_namespace(tmp_path: Path) -> None:\n''',
    '''\n\ndef test_runtime_dependency_state_stops_when_deadline_expires(\n    tmp_path: Path, monkeypatch: pytest.MonkeyPatch\n) -> None:\n    first = tmp_path / "a.py"\n    second = tmp_path / "b.py"\n    first.write_text("A = 1\\n", encoding="utf-8")\n    second.write_text("B = 1\\n", encoding="utf-8")\n    inventory = RuntimeTrustInventory(\n        trees=(),\n        namespace_roots=(),\n        security_paths=(),\n        files=(first, second),\n        distributions=(),\n    )\n\n    def slow_security_descriptor(_path: Path) -> None:\n        time.sleep(0.03)\n        return None\n\n    monkeypatch.setattr(\n        runtime_trust, "_security_descriptor_sha256", slow_security_descriptor\n    )\n\n    with pytest.raises(TimeoutError, match="operation deadline"):\n        capture_runtime_dependency_state(\n            max_files=10,\n            max_bytes=1024,\n            inventory=inventory,\n            deadline=time.monotonic() + 0.01,\n        )\n\n\ndef test_runtime_generation_identity_binds_source_namespace(tmp_path: Path) -> None:\n''',
    "runtime trust deadline regression",
)

# 7. Active-config integration diagnostics: if the child never reaches the intended tamper,
# pytest must print the actual operation/result state instead of only the unchanged config.
replace_once(
    "tests/test_active_config_security_integration.py",
    '''    assert config.read_text(encoding="utf-8").find("git_enabled = true") >= 0\n    assert result["status"] == "failed"\n''',
    '''    diagnostic = {"result": result, "operation": operation}\n    assert config.read_text(encoding="utf-8").find("git_enabled = true") >= 0, diagnostic\n    assert result["status"] == "failed", diagnostic\n''',
    "active config failure diagnostics",
)
