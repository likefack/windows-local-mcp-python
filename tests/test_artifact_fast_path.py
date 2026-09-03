from __future__ import annotations

import base64

import pytest

from windows_local_mcp.artifact_fast_path import (
    OneShotDigestMismatch,
    OneShotLimitExceeded,
    check_one_shot_size,
    decode_one_shot_upload,
    encode_one_shot_download,
)
from windows_local_mcp.util import sha256_bytes


def test_download_is_byte_exact_and_hash_bound() -> None:
    payload = b"\x00\xff\x01binary\r\n"

    result = encode_one_shot_download(
        payload,
        max_bytes=len(payload),
        path="reports/result.bin",
        expected_sha256=sha256_bytes(payload),
    )

    assert result["path"] == "reports/result.bin"
    assert result["bytes"] == len(payload)
    assert result["sha256"] == sha256_bytes(payload)
    assert result["execution_path"] == "one_shot"
    assert result["transfer_mode"] == "one_shot"
    assert base64.b64decode(result["base64"], validate=True) == payload


def test_download_limit_identifies_chunk_route_before_encoding() -> None:
    with pytest.raises(OneShotLimitExceeded) as raised:
        encode_one_shot_download(b"012345", max_bytes=5)

    error = raised.value
    assert error.direction == "download"
    assert error.actual == 6
    assert error.limit == 5
    assert error.unit == "bytes"
    assert "chunked transfer is required" in str(error)
    assert "artifact_download_begin" in error.chunked_route


def test_download_response_character_bound_is_enforced() -> None:
    # Four bytes require eight canonical base64 characters; the raw byte bound alone is not
    # sufficient to protect the MCP response envelope.
    with pytest.raises(OneShotLimitExceeded) as raised:
        encode_one_shot_download(b"1234", max_bytes=4, max_base64_chars=7)

    assert raised.value.unit == "base64_chars"
    assert raised.value.actual == 8
    assert raised.value.direction == "download"


def test_download_digest_assertion_rejects_stale_content() -> None:
    with pytest.raises(OneShotDigestMismatch, match="SHA-256 mismatch"):
        encode_one_shot_download(b"new", max_bytes=3, expected_sha256=sha256_bytes(b"old"))


def test_upload_preserves_declared_digest_and_destination_cas() -> None:
    payload = b"small upload with NUL \x00"
    encoded = base64.b64encode(payload).decode("ascii")
    expected = sha256_bytes(b"destination before")

    prepared = decode_one_shot_upload(
        encoded,
        max_bytes=len(payload),
        sha256=sha256_bytes(payload),
        expected_sha256=expected,
    )

    assert prepared.payload == payload
    assert prepared.bytes == len(payload)
    assert prepared.sha256 == sha256_bytes(payload)
    assert prepared.expected_sha256 == expected
    assert prepared.base64 == encoded
    assert prepared.summary() == {
        "bytes": len(payload),
        "sha256": sha256_bytes(payload),
        "expected_sha256": expected,
        "execution_path": "one_shot",
        "transfer_mode": "one_shot",
    }


def test_upload_rejects_digest_mismatch_without_returning_mutation_bytes() -> None:
    payload = b"declared content"
    with pytest.raises(OneShotDigestMismatch):
        decode_one_shot_upload(
            base64.b64encode(payload).decode("ascii"),
            max_bytes=1024,
            sha256=sha256_bytes(b"different content"),
        )


def test_upload_rejects_noncanonical_or_invalid_base64() -> None:
    digest = sha256_bytes(b"a")
    with pytest.raises(ValueError, match="canonical"):
        decode_one_shot_upload("YR==", max_bytes=10, sha256=digest)
    with pytest.raises(ValueError, match="valid canonical base64"):
        decode_one_shot_upload("not base64", max_bytes=100, sha256=digest)
    with pytest.raises(ValueError, match="ASCII"):
        decode_one_shot_upload("é", max_bytes=100, sha256=digest)


def test_upload_limits_are_checked_before_decode_and_explain_chunk_route() -> None:
    payload = b"0123456789"
    encoded = base64.b64encode(payload).decode("ascii")
    with pytest.raises(OneShotLimitExceeded) as raised:
        decode_one_shot_upload(
            encoded,
            max_bytes=len(payload),
            max_base64_chars=len(encoded) - 1,
            sha256=sha256_bytes(payload),
        )
    assert raised.value.direction == "upload"
    assert raised.value.unit == "base64_chars"
    assert "artifact_upload_begin" in raised.value.chunked_route

    with pytest.raises(OneShotLimitExceeded) as raw_raised:
        decode_one_shot_upload(
            encoded,
            max_bytes=len(payload) - 1,
            max_base64_chars=len(encoded),
            sha256=sha256_bytes(payload),
        )
    assert raw_raised.value.unit == "bytes"


def test_size_preflight_rejects_invalid_bounds_and_large_payload() -> None:
    check_one_shot_size(0, max_bytes=0, direction="download")
    with pytest.raises(OneShotLimitExceeded):
        check_one_shot_size(2, max_bytes=1, direction="upload")
    with pytest.raises(ValueError, match="non-negative integer"):
        check_one_shot_size(1, max_bytes=-1, direction="download")
    with pytest.raises(ValueError, match="non-negative integer"):
        check_one_shot_size(True, max_bytes=1, direction="download")
