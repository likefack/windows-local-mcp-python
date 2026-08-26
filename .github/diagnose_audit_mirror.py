from __future__ import annotations

import json
import shutil
from pathlib import Path

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp import control_plane_guard as guard
from windows_local_mcp.util import canonical_json

root = Path('.dev-tmp/audit-mirror-diag').resolve()
shutil.rmtree(root, ignore_errors=True)
workspace = root / 'workspace'
workspace.mkdir(parents=True)
settings = Settings(
    workspace_root=workspace,
    data_dir=root / 'data',
    protect_data_dir_acl=False,
    git_enabled=False,
)
settings.ensure_directories()
audit = AuditStore(settings)
operation = audit.create_operation(
    tool_name='host',
    tier='approved_host',
    status='running',
    cwd=str(workspace),
    request={'normalized_command': {'program_key': 'python'}},
    request_hash='a' * 64,
    approval_status='approved',
)

# This diagnostic isolates SQLite trusted-mirror behavior from runtime/ACL scan cost.
guard.capture_runtime_dependency_state = lambda **_kwargs: {
    'bytes': 0,
    'digest': '0' * 64,
    'file_count': 0,
}
guard._capture_runtime_startup_state = lambda *_args, **_kwargs: {
    'count': 0,
    'digest': '1' * 64,
}
guard._acl_state_digest = lambda *_args, **_kwargs: ('2' * 64, 0)

before = guard.capture_critical_state(settings, operation)
audit.add_event(operation, 'approved_host_control_plane_guard_armed', before)
audit.update_operation(operation, network_policy_json=canonical_json({'name': 'approved-host-network'}))
audit.add_event(operation, 'network_policy_applied', {'name': 'approved-host-network'})
audit.update_operation(
    operation,
    child_pid=1234,
    child_create_time=123.5,
    child_executable='C:\\Python\\python.exe',
)
audit.add_event(operation, 'child_started', {'child_pid': 1234, 'identity_verified': True})

identity = guard._database_identity(settings.data_dir / 'audit.db')
active = guard._ACTIVE_AUDIT_GUARDS[identity]
expected = guard._audit_snapshot_from_connection(active.mirror)
actual, _ = guard._audit_state_snapshot(settings)

print('BEFORE_SUMMARY', json.dumps(before, sort_keys=True))
print('EXPECTED', canonical_json(expected))
print('ACTUAL', canonical_json(actual))

if expected == actual:
    print('MIRROR_MATCH')
else:
    print('MIRROR_MISMATCH')
    for section in ('operations', 'events', 'sqlite_sequence', 'schema'):
        if expected[section] == actual[section]:
            continue
        print('DIFF_SECTION', section)
        print('EXPECTED_SECTION', canonical_json(expected[section]))
        print('ACTUAL_SECTION', canonical_json(actual[section]))

# Deactivate/close the guard cleanly for the runner.
after = guard.capture_critical_state(settings, operation)
print('AFTER_SUMMARY', json.dumps(after, sort_keys=True))
