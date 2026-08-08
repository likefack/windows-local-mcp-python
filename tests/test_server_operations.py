import importlib
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from windows_local_mcp.util import sha256_bytes


def load_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "workspace"
    root.mkdir()
    data = tmp_path / "data"
    config = tmp_path / "config.toml"
    config.write_text(
        "\n".join(
            [
                f'workspace_root = "{str(root).replace(chr(92), chr(92) * 2)}"',
                f'data_dir = "{str(data).replace(chr(92), chr(92) * 2)}"',
                "protect_data_dir_acl = false",
                "git_enabled = false",
                "max_write_bytes = 4096",
                "max_diff_bytes = 8192",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))
    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)
    sys.modules.pop("windows_local_mcp.server", None)
    server = importlib.import_module("windows_local_mcp.server")
    return server, root


def test_concurrent_write_with_same_expected_hash_has_one_winner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    target = root / "shared.txt"
    target.write_text("initial", encoding="utf-8")
    expected = sha256_bytes(b"initial")

    def write(value: str) -> str:
        try:
            server.write_file("shared.txt", value, expected_sha256=expected)
            return "succeeded"
        except RuntimeError as error:
            assert "expected_sha256 mismatch" in str(error)
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(write, ["first", "second"]))
    assert sorted(results) == ["conflict", "succeeded"]
    assert target.read_text(encoding="utf-8") in {"first", "second"}


def test_oversized_write_is_rejected_and_audited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, _ = load_server(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="max_write_bytes"):
        server.write_file("large.txt", "x" * 5000)
    records = server.runtime.audit.list_operations(limit=10)
    assert any(
        record["tool_name"] == "write_file" and record["status"] == "rejected"
        for record in records
    )


def test_denied_command_is_audited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    server, _ = load_server(tmp_path, monkeypatch)
    with pytest.raises(PermissionError):
        server.execute_readonly("python", ["-c", "print(1)"])
    records = server.runtime.audit.list_operations(limit=10)
    assert any(
        record["tool_name"] == "execute_readonly" and record["status"] == "rejected"
        for record in records
    )


def test_backup_and_diff_limits_fail_before_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, root = load_server(tmp_path, monkeypatch)
    target = root / "bounded.txt"
    original = "a\n" * 1000
    target.write_text(original, encoding="utf-8")
    server.runtime.settings.max_backup_bytes = 1024
    with pytest.raises(ValueError, match="max_backup_bytes"):
        server.write_file("bounded.txt", "small")
    assert target.read_text(encoding="utf-8") == original

    server.runtime.settings.max_backup_bytes = 4096
    server.runtime.settings.max_diff_bytes = 1024
    with pytest.raises(ValueError, match="max_diff_bytes"):
        server.write_file("bounded.txt", "b\n" * 1000)
    assert target.read_text(encoding="utf-8") == original
