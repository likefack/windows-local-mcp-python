"""Bounded, byte-exact helpers for the small-artifact one-shot path.

The artifact transfer tools in :mod:`windows_local_mcp.server` deliberately keep their
begin/chunk/commit protocol for large payloads.  This module only validates and encodes a
small payload.  In particular, it does not resolve workspace paths, acquire locks, or
write files.  Callers must keep using the existing workspace read guard for downloads and
``_atomic_binary_mutation`` (or the equivalent existing transaction path) for uploads.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any, Final, Literal

from .util import sha256_bytes

_SHA256_RE: Final = re.compile(r"[0-9a-f]{64}")
_DEFAULT_DOWNLOAD_ROUTE: Final = "artifact_download_begin + artifact_download_chunk"
_DEFAULT_UPLOAD_ROUTE: Final = (
    "artifact_upload_begin + artifact_upload_chunk + artifact_upload_commit"
)


class OneShotLimitExceeded(ValueError):
    """The payload cannot safely be returned or accepted as one MCP message.

    ``chunked_route`` is intentionally part of the exception.  A high-level server tool can
    surface the route directly to the caller instead of attempting a generic retry or
    silently falling back after a mutation has begun.
    """

    def __init__(
        self,
        *,
        direction: Literal["download", "upload"],
        actual: int,
        limit: int,
        unit: Literal["bytes", "base64_chars"],
        chunked_route: str,
    ) -> None:
        self.direction = direction
        self.actual = actual
        self.limit = limit
        self.unit = unit
        self.chunked_route = chunked_route
        super().__init__(
            f"one-shot {direction} {unit} limit exceeded: {actual} > {limit}; "
            f"chunked transfer is required ({chunked_route})"
        )


# A descriptive alias makes the intent clear at call sites while retaining one exception
# type for clients that want to catch the fast-path limit condition.
ChunkedTransferRequired = OneShotLimitExceeded


class OneShotDigestMismatch(ValueError):
    """The payload bytes do not match a caller-declared SHA-256 digest."""

    def __init__(self, *, expected: str, actual: str) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(f"one-shot payload SHA-256 mismatch: expected {expected}, got {actual}")


def _validate_limit(value: int, *, name: str) -> int:
    """Validate a non-negative configured bound without accepting ``bool`` as an integer."""

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _encoded_size(byte_count: int) -> int:
    """Return the canonical base64 character count for a byte count."""

    return ((byte_count + 2) // 3) * 4


def _validate_direction(
    direction: Literal["download", "upload"],
) -> Literal["download", "upload"]:
    if direction != "download" and direction != "upload":
        raise ValueError("direction must be 'download' or 'upload'")
    return direction


def _validate_digest(value: str, *, name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _check_encoded_limit(
    encoded_size: int,
    *,
    max_base64_chars: int,
    direction: Literal["download", "upload"],
) -> None:
    if encoded_size > max_base64_chars:
        raise OneShotLimitExceeded(
            direction=direction,
            actual=encoded_size,
            limit=max_base64_chars,
            unit="base64_chars",
            chunked_route=(
                _DEFAULT_DOWNLOAD_ROUTE if direction == "download" else _DEFAULT_UPLOAD_ROUTE
            ),
        )


def _check_byte_limit(
    byte_count: int,
    *,
    max_bytes: int,
    direction: Literal["download", "upload"],
) -> None:
    if byte_count > max_bytes:
        raise OneShotLimitExceeded(
            direction=direction,
            actual=byte_count,
            limit=max_bytes,
            unit="bytes",
            chunked_route=(
                _DEFAULT_DOWNLOAD_ROUTE if direction == "download" else _DEFAULT_UPLOAD_ROUTE
            ),
        )


def check_one_shot_size(
    byte_count: int,
    *,
    max_bytes: int,
    direction: Literal["download", "upload"],
) -> None:
    """Preflight a raw payload size before reading or mutating it.

    The server can use this with a verified file identity before opening a source file.  That
    avoids reading a large artifact merely to discover that a one-shot response is not allowed.
    """

    _validate_direction(direction)
    _validate_limit(max_bytes, name="max_bytes")
    if isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count < 0:
        raise ValueError("byte_count must be a non-negative integer")
    _check_byte_limit(byte_count, max_bytes=max_bytes, direction=direction)


@dataclass(frozen=True, slots=True)
class PreparedOneShotUpload:
    """Validated upload bytes ready for the existing CAS/transaction mutation helper.

    ``payload`` is immutable-by-convention bytes.  The object deliberately contains no path,
    lock, checkpoint, or transaction state; the caller must pass ``expected_sha256`` to the
    existing mutation primitive and use its rollback result unchanged.
    """

    payload: bytes
    sha256: str
    expected_sha256: str | None
    encoded: str

    @property
    def bytes(self) -> int:
        return len(self.payload)

    @property
    def base64(self) -> str:
        return self.encoded

    def summary(self) -> dict[str, Any]:
        """Return safe metadata suitable for an audit/result summary."""

        return {
            "bytes": self.bytes,
            "sha256": self.sha256,
            "expected_sha256": self.expected_sha256,
            "execution_path": "one_shot",
            "transfer_mode": "one_shot",
        }


def encode_one_shot_download(
    payload: bytes,
    *,
    max_bytes: int,
    path: str | None = None,
    expected_sha256: str | None = None,
    max_base64_chars: int | None = None,
) -> dict[str, Any]:
    """Encode a verified small artifact without exceeding request/response bounds.

    ``payload`` must already have been read through the existing workspace verification path.
    An optional ``expected_sha256`` is a source-content assertion; it does not replace the
    path identity and same-handle checks performed by the caller.
    """

    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    _validate_limit(max_bytes, name="max_bytes")
    if max_base64_chars is None:
        max_base64_chars = _encoded_size(max_bytes)
    _validate_limit(max_base64_chars, name="max_base64_chars")
    check_one_shot_size(len(payload), max_bytes=max_bytes, direction="download")

    actual_sha256 = sha256_bytes(payload)
    if expected_sha256 is not None:
        expected_sha256 = _validate_digest(expected_sha256, name="expected_sha256")
        if actual_sha256 != expected_sha256:
            raise OneShotDigestMismatch(expected=expected_sha256, actual=actual_sha256)

    encoded = base64.b64encode(payload).decode("ascii")
    _check_encoded_limit(
        len(encoded), max_base64_chars=max_base64_chars, direction="download"
    )
    result: dict[str, Any] = {
        "bytes": len(payload),
        "sha256": actual_sha256,
        "base64": encoded,
        "execution_path": "one_shot",
        "transfer_mode": "one_shot",
    }
    if path is not None:
        result["path"] = path
    return result


def decode_one_shot_upload(
    encoded: str,
    *,
    max_bytes: int,
    sha256: str,
    expected_sha256: str | None = None,
    max_base64_chars: int | None = None,
) -> PreparedOneShotUpload:
    """Validate an exact base64 upload before an existing CAS-bound mutation.

    ``sha256`` is the declared digest of the uploaded bytes and must match.  ``expected_sha256``
    is retained as the destination's pre-mutation CAS value; this helper validates its shape but
    intentionally does not inspect or mutate a workspace path.  The caller must pass it through
    to the existing transactional commit helper.
    """

    _validate_limit(max_bytes, name="max_bytes")
    if max_base64_chars is None:
        max_base64_chars = _encoded_size(max_bytes)
    _validate_limit(max_base64_chars, name="max_base64_chars")
    declared_sha256 = _validate_digest(sha256, name="sha256")
    if expected_sha256 is not None:
        expected_sha256 = _validate_digest(expected_sha256, name="expected_sha256")
    if not isinstance(encoded, str):
        raise TypeError("base64 payload must be a string")
    if any(ord(character) > 127 for character in encoded):
        raise ValueError("base64 payload must contain ASCII characters only")
    _check_encoded_limit(
        len(encoded), max_base64_chars=max_base64_chars, direction="upload"
    )

    try:
        payload = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("base64 payload must be valid canonical base64") from error
    # Re-encoding rejects alternate spellings (including non-zero padding bits) and guarantees
    # that the exact bytes represented by the request are the bytes committed by the caller.
    if base64.b64encode(payload).decode("ascii") != encoded:
        raise ValueError("base64 payload must use canonical padding and alphabet")

    check_one_shot_size(len(payload), max_bytes=max_bytes, direction="upload")
    actual_sha256 = sha256_bytes(payload)
    if actual_sha256 != declared_sha256:
        raise OneShotDigestMismatch(expected=declared_sha256, actual=actual_sha256)
    return PreparedOneShotUpload(
        payload=payload,
        sha256=actual_sha256,
        expected_sha256=expected_sha256,
        encoded=encoded,
    )


__all__ = [
    "ChunkedTransferRequired",
    "OneShotDigestMismatch",
    "OneShotLimitExceeded",
    "PreparedOneShotUpload",
    "check_one_shot_size",
    "decode_one_shot_upload",
    "encode_one_shot_download",
]
