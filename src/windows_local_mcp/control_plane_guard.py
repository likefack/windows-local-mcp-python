from __future__ import annotations

import os
import sqlite3
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .config import Settings
from .config_binding import export_config_binding
from .util import canonical_json, sha256_bytes, sha256_text, utc_now_iso
from .windows_system import windows_system_executable


def _is_reparse(path: Path) -> bool:
    details = path.lstat()
    attributes = int(getattr(details, "st_file_attributes", 0))
    return path.is_symlink() or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _tamper_marker(settings: Settings) -> Path:
    return settings.data_dir / "control-plane" / "tamper-detected.json"


def assert_control_plane_healthy(settings: Settings) -> None:
    if _tamper_marker(settings).exists():
        raise RuntimeError(
            "control-plane tampering was previously detected; operations are unavailable "
            "until the operator performs an explicit recovery"
        )


def capture_critical_state(settings: Settings, operation_id: str) -> dict[str, Any]:
    """Capture state that an Approved Host child is never allowed to mutate."""
    config_binding = export_config_binding(settings)
    roots = [
        settings.data_dir / "approval-staging",
        settings.data_dir / "binary-transfers",
        settings.data_dir / "worker-contexts" / f"{operation_id}.json",
        settings.data_dir / "control-plane",
        settings.data_dir / "workspace-history",
        Path(__file__).resolve(strict=True).parent,
    ]
    if settings.sandbox_scratch_dir is not None:
        roots.append(settings.sandbox_scratch_dir / "approval-inputs")
        runs = settings.sandbox_scratch_dir / "runs"
        if runs.is_dir():
            roots.extend(
                child
                for child in runs.iterdir()
                if child.name != operation_id
            )
    config_path = config_binding.get("config_path")
    if config_path:
        roots.append(Path(str(config_path)).resolve(strict=True))
    records: list[dict[str, Any]] = []
    total_bytes = 0
    for root in roots:
        if not root.exists():
            continue
        candidates: list[Path] = []
        if root.is_file():
            candidates.append(root)
        else:
            for current, directories, files in os.walk(root, followlinks=False):
                current_path = Path(current)
                for name in directories:
                    if _is_reparse(current_path / name):
                        raise RuntimeError(
                            "control-plane state contains a reparse directory"
                        )
                candidates.extend(current_path / name for name in files)
        for path in sorted(candidates, key=lambda item: str(item).casefold()):
            if path == _tamper_marker(settings):
                continue
            if _is_reparse(path) or not path.is_file() or path.stat().st_nlink > 1:
                raise RuntimeError("control-plane state contains an unsafe file identity")
            data = path.read_bytes()
            total_bytes += len(data)
            if len(records) + 1 > settings.approval_manifest_max_files:
                raise RuntimeError("control-plane state exceeds the file admission limit")
            if total_bytes > settings.approval_manifest_max_bytes:
                raise RuntimeError("control-plane state exceeds the byte admission limit")
            try:
                record_path = str(path.relative_to(settings.data_dir)).replace("\\", "/")
            except ValueError:
                record_path = str(path.resolve(strict=True))
            records.append(
                {
                    "path": record_path,
                    "bytes": len(data),
                    "sha256": sha256_bytes(data),
                }
            )
    audit_digest, audit_bytes = _audit_state_digest(settings, operation_id)
    acl_digest, acl_bytes = _acl_state_digest(settings, roots)
    return {
        "file_count": len(records),
        "bytes": total_bytes + audit_bytes + acl_bytes,
        "digest": sha256_text(
            canonical_json(
                {
                    "files": records,
                    "audit_digest": audit_digest,
                    "acl_digest": acl_digest,
                    "config_binding": config_binding,
                }
            )
        ),
        "audit_digest": audit_digest,
        "acl_digest": acl_digest,
        "config_binding": config_binding,
    }


def _acl_state_digest(settings: Settings, roots: list[Path]) -> tuple[str | None, int]:
    if os.name != "nt":
        return None, 0
    chunks: list[bytes] = []
    total = 0
    for root in roots:
        if not root.exists():
            continue
        completed = subprocess.run(
            [windows_system_executable("icacls.exe"), str(root), "/T", "/C"],
            capture_output=True,
            timeout=30,
            check=False,
            shell=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"could not inspect control-plane ACL: {root}")
        payload = completed.stdout + completed.stderr
        total += len(payload)
        if total > settings.approval_manifest_max_bytes:
            raise RuntimeError("control-plane ACL state exceeds the byte admission limit")
        chunks.append(str(root.resolve(strict=True)).encode("utf-8") + b"\0" + payload)
    return sha256_bytes(b"\0".join(chunks)), total


def _audit_state_digest(settings: Settings, operation_id: str) -> tuple[str, int]:
    database = settings.data_dir / "audit.db"
    if not database.is_file():
        raise RuntimeError("audit database disappeared before Approved Host execution")
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=10)
    try:
        integrity = connection.execute("PRAGMA quick_check").fetchone()
        if integrity != ("ok",):
            raise RuntimeError("audit database integrity check failed")
        rows: list[object] = []
        schema = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
        rows.append(schema)
        rows.append(
            connection.execute(
                "SELECT id, session_id, tool_name, tier, cwd, request_json, request_hash, "
                "approval_status, approval_by, approved_at, approval_expires_at, claimed_at "
                "FROM operations WHERE id = ?",
                (operation_id,),
            ).fetchall()
        )
        rows.append(
            connection.execute(
                "SELECT * FROM operations WHERE id <> ? ORDER BY id", (operation_id,)
            ).fetchall()
        )
        rows.append(
            connection.execute(
                "SELECT * FROM events WHERE operation_id <> ? ORDER BY id", (operation_id,)
            ).fetchall()
        )
        payload = canonical_json(rows).encode("utf-8")
        if len(payload) > settings.max_data_dir_bytes:
            raise RuntimeError("audit state exceeds the control-plane verification bound")
        return sha256_bytes(payload), len(payload)
    finally:
        connection.close()


def mark_control_plane_tamper(
    settings: Settings,
    operation_id: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> str:
    marker = _tamper_marker(settings)
    marker.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json(
        {
            "version": 1,
            "detected_at": utc_now_iso(),
            "operation_id": operation_id,
            "before": before,
            "after": after,
            "recovery": "manual operator review required",
        }
    ).encode("utf-8")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=marker.parent) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
            temporary = Path(output.name)
        os.replace(temporary, marker)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return str(marker)
