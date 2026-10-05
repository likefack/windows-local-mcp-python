import base64
import json
from pathlib import Path
from typing import Any

import pytest

from windows_local_mcp.audit import AuditStore
from windows_local_mcp.config import Settings
from windows_local_mcp.operation_changes import (
    build_operation_changes,
    iter_operation_diff_lines,
)
from windows_local_mcp.util import canonical_json, sha256_bytes
from windows_local_mcp.workspace_history import capture_workspace_state, compare_workspace_states


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    root = tmp_path / "workspace"
    root.mkdir()
    settings = Settings(
        workspace_root=root, data_dir=tmp_path / "data", protect_data_dir_acl=False,
        **overrides,
    )
    settings.ensure_directories()
    return settings


def _operation(
    settings: Settings, before_files: dict[str, bytes], after_files: dict[str, bytes],
    *, before_directories: tuple[str, ...] = (), after_directories: tuple[str, ...] = (),
) -> tuple[AuditStore, str, dict[str, Any]]:
    audit = AuditStore(settings)
    operation_id = audit.create_operation(
        tool_name="workspace_apply", tier="broker", status="running",
        cwd=str(settings.workspace_root), request={},
    )
    for relative in before_directories:
        (settings.workspace_root / relative).mkdir(parents=True, exist_ok=True)
    for relative, data in before_files.items():
        target = settings.workspace_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    before = capture_workspace_state(settings, operation_id, "before")
    for relative in before_files.keys() - after_files.keys():
        (settings.workspace_root / relative).unlink()
    for relative in sorted(set(before_directories) - set(after_directories), reverse=True):
        (settings.workspace_root / relative).rmdir()
    for relative in after_directories:
        (settings.workspace_root / relative).mkdir(parents=True, exist_ok=True)
    for relative, data in after_files.items():
        target = settings.workspace_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    after = capture_workspace_state(settings, operation_id, "after")
    changes = compare_workspace_states(settings, before.manifest_path, after.manifest_path, operation_id)
    audit.update_operation(
        operation_id, status="succeeded", pre_workspace_path=before.manifest_path,
        post_workspace_path=after.manifest_path, diff_path=changes["diff_path"],
        result_json=canonical_json(changes),
    )
    return audit, operation_id, changes


def _decoded_page(page: dict[str, Any]) -> bytes:
    return (
        base64.b64decode(page["content"], validate=True)
        if page["encoding"] == "base64" else page["content"].encode("utf-8")
    )


def _full_content(
    settings: Settings, audit: AuditStore, operation_id: str, path: str, view: str,
    *, max_bytes: int = 257,
) -> bytes:
    result = bytearray()
    offset = 0
    while True:
        page = build_operation_changes(
            settings, audit, operation_id, path=path, view=view,
            content_offset=offset, max_bytes=max_bytes,
        )
        assert page["availability"] == "available"
        chunk = _decoded_page(page)
        assert len(chunk) <= max_bytes
        assert sha256_bytes(chunk) == page["chunk_sha256"]
        assert page["bytes"] == len(chunk)
        result.extend(chunk)
        if page["eof"]:
            assert page["next_offset"] is None
            assert len(result) == page["total_bytes"]
            assert sha256_bytes(bytes(result)) == page["sha256"]
            return bytes(result)
        assert page["next_offset"] > offset
        offset = page["next_offset"]


def test_complete_diff_and_counts_survive_preview_limit(tmp_path: Path) -> None:
    settings = _settings(tmp_path, max_diff_bytes=1024)
    old = b"".join(f"old line {i}\n".encode() for i in range(100))
    new = b"".join(f"new line {i}\n".encode() for i in range(100))
    audit, operation_id, result = _operation(
        settings, {"a.txt": old, "z.txt": b"--old\n", "n.bin": b"a\x00"},
        {"a.txt": new, "z.txt": b"++new\n", "n.bin": b"b\x00", "empty.txt": b""},
    )
    assert result["diff_truncated"] is True
    assert Path(result["diff_path"]).stat().st_size <= settings.max_diff_bytes
    assert Path(result["diff_path"]).stat().st_size == result["diff_preview_bytes"]
    assert result["added_lines"] == result["removed_lines"] == 101
    assert result["text_file_count"] == 3
    assert result["nontext_file_count"] == 1
    assert result["bytes_before"] == len(old) + len(b"--old\n") + 2
    assert result["bytes_after"] == len(new) + len(b"++new\n") + 2
    complete = "".join(iter_operation_diff_lines(settings, audit.get_operation(operation_id)))
    assert len(complete.encode()) == result["diff_bytes"]
    assert "+++new\n" in complete
    assert "Binary files differ: n.bin\n" in complete
    assert "new file mode 100644\n" in complete
    reconstructed = _full_content(settings, audit, operation_id, "a.txt", "diff")
    assert b"+new line 99\n" in reconstructed
    assert b"truncated" not in reconstructed


def test_path_listing_is_complete_and_paged_without_current_workspace_reads(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    audit, operation_id, _ = _operation(
        settings, {"gone.txt": b"old", "same.txt": b"same"},
        {"new.txt": b"new", "same.txt": b"same"},
        before_directories=("old_dir",), after_directories=("new_dir",),
    )
    # Later workspace edits do not become part of the saved operation.
    (settings.workspace_root / "new.txt").write_bytes(b"unrelated later edit")
    (settings.workspace_root / "later.txt").write_bytes(b"later")
    pages = [build_operation_changes(settings, audit, operation_id, offset=i, limit=1) for i in range(4)]
    assert [p["changes"][0]["path"] for p in pages] == ["gone.txt", "new.txt", "new_dir", "old_dir"]
    assert [p["next_offset"] for p in pages] == [1, 2, 3, None]
    assert pages[-1]["eof"] is True
    assert pages[0]["changed_file_count"] == pages[0]["changed_directory_count"] == 2
    assert pages[0]["manifest_binding"] == "verified"
    assert pages[0]["content_integrity"] == "not_read"
    assert _full_content(settings, audit, operation_id, "new.txt", "after") == b"new"
    assert pages[-1]["changes"][0]["before"]["kind"] == "directory"


@pytest.mark.parametrize("old,new", [(b"\x00a\xff\r\n", b"\x00b\xfe\r\n"), (b"\x00", b"\x01")])
def test_binary_before_after_are_exact_base64_bytes(tmp_path: Path, old: bytes, new: bytes) -> None:
    settings = _settings(tmp_path)
    audit, operation_id, result = _operation(settings, {"file.bin": old}, {"file.bin": new})
    assert result["nontext_file_count"] == 1
    assert result["added_lines"] == result["removed_lines"] == 0
    assert _full_content(settings, audit, operation_id, "file.bin", "before", max_bytes=2) == old
    assert _full_content(settings, audit, operation_id, "file.bin", "after", max_bytes=2) == new
    summary = build_operation_changes(settings, audit, operation_id, path="file.bin")
    assert summary["diff_kind"] == "binary_summary"
    assert summary["diff_content_complete"] is False


def test_crlf_and_no_final_newline_are_preserved_in_complete_diff(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    before = "共通\r\n削除\r\n末尾".encode()
    after = "共通\r\n追加\r\n末尾改訂".encode()
    audit, operation_id, result = _operation(settings, {"a.txt": before}, {"a.txt": after})
    diff = _full_content(settings, audit, operation_id, "a.txt", "diff", max_bytes=7)
    assert b"\r\r\n" not in diff
    assert "-削除\r\n".encode() in diff
    assert "+追加\r\n".encode() in diff
    assert diff.count(b"\\ No newline at end of file\n") == 2
    assert Path(result["diff_path"]).read_bytes() == diff
    assert result["added_lines"] == result["removed_lines"] == 2
    assert _full_content(settings, audit, operation_id, "a.txt", "after") == after
    lines = list(iter_operation_diff_lines(settings, audit.get_operation(operation_id)))
    assert all(line.endswith("\n") and "\n" not in line[:-1] for line in lines)


def test_unicode_line_separators_are_content_not_newlines(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    audit, operation_id, result = _operation(
        settings, {"a.txt": "a\u2028b\n".encode()}, {"a.txt": "c\u2028d\n".encode()}
    )
    assert result["added_lines"] == result["removed_lines"] == 1
    assert "+c\u2028d\n" in "".join(iter_operation_diff_lines(settings, audit.get_operation(operation_id)))


def test_empty_creation_deletion_and_directory_changes_are_visible(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    audit, operation_id, result = _operation(
        settings, {"deleted.txt": b""}, {"added.txt": b""},
        before_directories=("deleted_dir",), after_directories=("added_dir",),
    )
    diff = "".join(iter_operation_diff_lines(settings, audit.get_operation(operation_id)))
    assert "new file mode 100644\n" in diff
    assert "deleted file mode 100644\n" in diff
    assert "Directory added: added_dir\n" in diff
    assert "Directory removed: deleted_dir\n" in diff
    assert result["added_lines"] == result["removed_lines"] == 0
    assert _full_content(settings, audit, operation_id, "added.txt", "after") == b""
    missing = build_operation_changes(settings, audit, operation_id, path="added.txt", view="before")
    directory = build_operation_changes(settings, audit, operation_id, path="added_dir", view="after")
    assert missing["availability"] == directory["availability"] == "not_applicable"
    assert missing["reason"] == "path_absent"
    assert directory["reason"] == "directory_has_no_bytes"


def test_manifest_hash_binding_rejects_modified_history(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    audit, operation_id, _ = _operation(settings, {"a.txt": b"old"}, {"a.txt": b"new"})
    manifest_path = Path(audit.get_operation(operation_id)["post_workspace_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["path"] = "renamed.txt"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(RuntimeError, match="manifest integrity"):
        build_operation_changes(settings, audit, operation_id)


def test_same_size_blob_tamper_is_rejected_before_return(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    audit, operation_id, _ = _operation(settings, {"a.txt": b"old"}, {"a.txt": b"new"})
    blob = settings.data_dir / "workspace-history" / "blobs" / f"{sha256_bytes(b'new')}.blob"
    blob.write_bytes(b"BAD")
    with pytest.raises(RuntimeError, match="content integrity"):
        build_operation_changes(settings, audit, operation_id, path="a.txt", view="after")
    with pytest.raises(RuntimeError, match="content integrity"):
        list(iter_operation_diff_lines(settings, audit.get_operation(operation_id)))


@pytest.mark.parametrize("change", ["identity", "scope", "blob", "protected", "size", "namespace"])
def test_unbound_legacy_manifest_still_checks_namespace_schema_and_policy(tmp_path: Path, change: str) -> None:
    settings = _settings(tmp_path)
    audit, operation_id, _ = _operation(settings, {"a.txt": b"old"}, {"a.txt": b"new"})
    operation = audit.get_operation(operation_id)
    manifest_path = Path(operation["post_workspace_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if change == "identity":
        manifest["operation_id"] = "another-operation"
    elif change == "scope":
        manifest["scope"] = {"kind": "paths", "paths": ["another.txt"]}
    elif change == "blob":
        manifest["files"][0]["blob"] = "../outside"
    elif change == "protected":
        manifest["files"][0]["path"] = ".env"
    elif change == "size":
        manifest["files"][0]["size"] = settings.approval_manifest_max_bytes + 1
    elif change == "namespace":
        manifest_path = settings.data_dir / "workspace-history" / "outside.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    audit.update_operation(operation_id, result_json="{}", post_workspace_path=str(manifest_path))
    with pytest.raises((ValueError, PermissionError, RuntimeError)):
        build_operation_changes(settings, audit, operation_id, path="a.txt")


@pytest.mark.parametrize("path", ["../outside", "C:\\outside", "a.txt:ads", ".git/config", ".env"])
def test_requested_paths_cannot_bypass_checkpoint_policy(tmp_path: Path, path: str) -> None:
    settings = _settings(tmp_path)
    audit, operation_id, _ = _operation(settings, {"a.txt": b"old"}, {"a.txt": b"new"})
    with pytest.raises((ValueError, PermissionError)):
        build_operation_changes(settings, audit, operation_id, path=path)


def test_missing_history_reports_unavailability_without_live_fallback(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    audit, operation_id, _ = _operation(settings, {"a.txt": b"old"}, {"a.txt": b"new"})
    Path(audit.get_operation(operation_id)["post_workspace_path"]).unlink()
    result = build_operation_changes(settings, audit, operation_id, path="a.txt")
    assert result["availability"] == "unavailable"
    assert result["complete"] is False
    assert result["reason"] == "checkpoint_missing_or_expired"
    assert "content" not in result


def test_missing_blob_reports_unavailability_and_legacy_binding_is_explicit(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    audit, operation_id, _ = _operation(settings, {"a.txt": b"old"}, {"a.txt": b"new"})
    audit.update_operation(operation_id, result_json="{}")
    listing = build_operation_changes(settings, audit, operation_id)
    assert listing["manifest_binding"] == "unrecorded"
    (settings.data_dir / "workspace-history" / "blobs" / f"{sha256_bytes(b'old')}.blob").unlink()
    result = build_operation_changes(settings, audit, operation_id, path="a.txt", view="before")
    assert result["availability"] == "unavailable"
    assert result["reason"] == "checkpoint_content_missing_or_expired"


def test_raw_page_needs_only_selected_side_and_clamps_default_page_size(tmp_path: Path) -> None:
    settings = _settings(tmp_path, max_transfer_chunk_bytes=4096)
    data = b"\x00" * 9000
    audit, operation_id, _ = _operation(settings, {"a.bin": b"old"}, {"a.bin": data})
    # An expired other side does not prevent exact bytes of the requested retained side.
    (settings.data_dir / "workspace-history" / "blobs" / f"{sha256_bytes(b'old')}.blob").unlink()
    page = build_operation_changes(settings, audit, operation_id, path="a.bin", view="after")
    assert page["availability"] == "available"
    assert page["max_bytes"] == page["bytes"] == page["next_offset"] == 4096
    assert _decoded_page(page) == data[:4096]


@pytest.mark.parametrize("status,rollback_state", [
    ("running", None), ("failed", "failed_recovered"), ("failed", "recovery_required"),
])
def test_history_completeness_is_distinct_from_operation_success(
    tmp_path: Path, status: str, rollback_state: str | None
) -> None:
    settings = _settings(tmp_path)
    audit, operation_id, _ = _operation(settings, {"a.txt": b"old"}, {"a.txt": b"new"})
    audit.update_operation(operation_id, status=status, rollback_state=rollback_state)
    page = build_operation_changes(settings, audit, operation_id)
    assert page["status"] == status
    assert page["rollback_state"] == (rollback_state or "not_applicable")
    assert page["completeness_scope"] == "recorded_checkpoint_pair"


@pytest.mark.parametrize("arguments", [
    {"offset": -1}, {"limit": 0}, {"limit": 201}, {"content_offset": -1},
    {"max_bytes": 0}, {"max_bytes": 999999999}, {"view": "live"}, {"offset": True},
])
def test_paging_arguments_are_bounded(tmp_path: Path, arguments: dict[str, Any]) -> None:
    settings = _settings(tmp_path)
    audit = AuditStore(settings)
    with pytest.raises(ValueError):
        build_operation_changes(settings, audit, "no-operation-read-needed", **arguments)
