from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, *, max_bytes: int | None = None) -> tuple[str, int]:
    """Hash a regular file with bounded memory and an optional byte limit."""
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise ValueError(f"file exceeds byte limit: {total} > {max_bytes}")
            digest.update(chunk)
    return digest.hexdigest(), total


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def read_text_limited(path: Path, max_bytes: int) -> str:
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"ファイルが大きすぎます: {size} bytes > {max_bytes} bytes")
    with path.open("r", encoding="utf-8", newline="") as source:
        return source.read()


def truncate_middle(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    half = max(1, (limit - 80) // 2)
    return value[:half] + "\n... <truncated> ...\n" + value[-half:]
