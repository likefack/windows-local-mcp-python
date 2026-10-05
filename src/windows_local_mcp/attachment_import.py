"""Bounded retrieval of OpenAI fileParams references from operator-pinned hosts.

fileParams is a delivery convention, not cryptographic proof of conversation membership.
No host is implicitly trusted. URLs, response headers and network exceptions are never
included in errors, results, or persistent state. File bytes remain opaque and unexecuted.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .artifact_errors import ArtifactTransferError

FILE_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "download_url": {"type": "string"},
        "file_id": {"type": "string"},
        "mime_type": {"type": "string"},
        "file_name": {"type": "string"},
    },
    "required": ["download_url", "file_id"],
    "additionalProperties": False,
}


def _reject(code: str, message: str) -> ArtifactTransferError:
    return ArtifactTransferError(code, message)


def validate_allowed_hosts(hosts: list[str]) -> list[str]:
    """Accept exact DNS names only; never expand a wildcard or a URL into authority."""
    result = []
    for host in hosts:
        if (
            not isinstance(host, str)
            or len(host) > 253
            or host != host.lower()
            or not re.fullmatch(r"[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?", host)
            or "." not in host
            or any(
                not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                for label in host.split(".")
            )
        ):
            raise ValueError("attachment hosts must be exact lowercase DNS names")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("attachment hosts cannot be IP literals")
        if host not in result:
            result.append(host)
    return result


def validate_reference(file: Any, allowed_hosts: list[str]) -> tuple[str, str]:
    """Validate manually so invalid file objects cannot be echoed by schema errors."""
    if not isinstance(file, dict) or set(file) - set(FILE_INPUT_SCHEMA["properties"]):
        raise _reject("ATTACHMENT_REFERENCE_REJECTED", "invalid file reference")
    for key in ("download_url", "file_id"):
        if not isinstance(file.get(key), str) or not file[key]:
            raise _reject("ATTACHMENT_REFERENCE_REJECTED", "missing file reference field")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", file["file_id"]):
        raise _reject("ATTACHMENT_REFERENCE_REJECTED", "invalid file identifier")
    for key in ("mime_type", "file_name"):
        if key in file and (not isinstance(file[key], str) or len(file[key]) > 1024):
            raise _reject("ATTACHMENT_REFERENCE_REJECTED", "invalid file metadata")
    url = file["download_url"]
    if len(url) > 8192 or any(ord(c) <= 32 or ord(c) >= 127 for c in url) or "\\" in url:
        raise _reject("ATTACHMENT_REFERENCE_REJECTED", "invalid download URL")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        valid = (
            parsed.scheme == "https"
            and host is not None
            and parsed.netloc in (host, host + ":443")
            and parsed.port in (None, 443)
            and not parsed.fragment
            and parsed.path.startswith("/")
            and parsed.path != "/"
        )
    except ValueError:
        valid = False
        host = None
    if not valid:
        raise _reject("ATTACHMENT_REFERENCE_REJECTED", "HTTPS file URL on port 443 required")
    if not allowed_hosts:
        raise _reject("ATTACHMENT_IMPORT_NOT_CONFIGURED", "operator-approved file hosts required")
    if host not in allowed_hosts:
        raise _reject("ATTACHMENT_REFERENCE_REJECTED", "file host is not permitted")
    return host, parsed.path + ("?" + parsed.query if parsed.query else "")


def _public_addresses(host: str) -> list[tuple[int, int, int, str, tuple]]:
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not addresses or len(addresses) > 32:
        raise _reject("ATTACHMENT_ADDRESS_REJECTED", "invalid destination address set")
    for family, _kind, _protocol, _name, address in addresses:
        ip = ipaddress.ip_address(address[0])
        # Reject transition/mapped addresses too: their embedded target may be private.
        if (
            family not in (socket.AF_INET, socket.AF_INET6)
            or not ip.is_global
            or ip.is_multicast
            or ip.is_reserved
            or (
                isinstance(ip, ipaddress.IPv6Address)
                and (
                    ip.ipv4_mapped is not None
                    or ip.sixtofour is not None
                    or ip.teredo is not None
                    or address[3] != 0
                )
            )
        ):
            raise _reject("ATTACHMENT_ADDRESS_REJECTED", "destination must use public IP addresses")
    return addresses


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect only to the already checked numeric address; retain TLS hostname checks."""

    def __init__(self, host: str, address: tuple, *, timeout: float) -> None:
        super().__init__(host, port=443, timeout=timeout, context=ssl.create_default_context())
        self._address = address
        self.active_socket = None

    def connect(self) -> None:
        family, kind, protocol, _name, sockaddr = self._address
        sock = socket.socket(family, kind, protocol)
        try:
            self.sock = sock
            self.active_socket = sock
            sock.settimeout(self.timeout)
            sock.connect(sockaddr)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
            self.active_socket = self.sock
        except BaseException:
            sock.close()
            raise


@dataclass(frozen=True)
class DownloadedAttachment:
    payload: bytes
    sha256: str
    detected_mime_type: str


def _interrupt_connection(connection: _PinnedHTTPSConnection) -> None:
    """Bound even slowly trickling headers; socket timeouts alone reset on each read."""
    # HTTPConnection may detach its socket on a Connection: close response while
    # HTTPResponse still owns a readable file object for that very same socket.
    sock = getattr(connection, "active_socket", connection.sock)
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  # A concurrent normal close is harmless.


def _detect_media_type(payload: bytes) -> str:
    # These are byte signatures, not a safety certification or a parser invocation.
    if payload.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if payload.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if payload.startswith(b"RIFF") and payload[8:12] == b"WEBP":
        return "image/webp"
    if payload.startswith(b"%PDF-"):
        return "application/pdf"
    if payload.startswith(b"PK\x03\x04"):
        return "application/zip"
    return "application/octet-stream"


def download_attachment(
    file: Any,
    *,
    allowed_hosts: list[str],
    max_bytes: int,
    expected_sha256: str | None = None,
    timeout_seconds: float = 60,
) -> DownloadedAttachment:
    """Receive raw bytes with a live size bound and incremental SHA-256, without Base64.

    The configured whole-file cap also bounds memory. This intentionally uses no URL
    opener, ambient proxy, cookies, auth headers, decompressor or redirect handler.
    """
    host, request_target = validate_reference(file, allowed_hosts)
    if expected_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise _reject("ATTACHMENT_SHA256_INVALID", "sha256 must be a lowercase SHA-256 digest")
    if max_bytes < 0 or timeout_seconds <= 0:
        raise _reject("ATTACHMENT_LIMIT_INVALID", "invalid attachment resource limits")
    connection = None
    response = None
    timer = None
    try:
        deadline = time.monotonic() + timeout_seconds
        addresses = _public_addresses(host)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        connection = _PinnedHTTPSConnection(host, addresses[0], timeout=min(10, remaining))
        timer = threading.Timer(remaining, _interrupt_connection, args=(connection,))
        timer.daemon = True
        timer.start()
        connection.request("GET", request_target, headers={"Accept-Encoding": "identity"})
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise _reject("ATTACHMENT_REDIRECT_REJECTED", "file redirects are not permitted")
        if response.status != 200:
            raise _reject(
                "ATTACHMENT_FETCH_FAILED", "file service did not return a successful response"
            )
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise _reject(
                "ATTACHMENT_ENCODING_REJECTED", "encoded response bodies are not permitted"
            )
        lengths = response.headers.get_all("Content-Length", [])
        transfer = response.getheader("Transfer-Encoding")
        if (
            len(lengths) > 1
            or (transfer and lengths)
            or (transfer and transfer.lower() != "chunked")
        ):
            raise _reject("ATTACHMENT_LENGTH_INVALID", "ambiguous response framing")
        if not lengths and not transfer and expected_sha256 is None:
            # EOF alone cannot distinguish a complete file from a broken connection.
            raise _reject(
                "ATTACHMENT_LENGTH_REQUIRED", "response framing or a source SHA-256 is required"
            )
        declared = None
        if lengths:
            if not re.fullmatch(r"[0-9]{1,20}", lengths[0]):
                raise _reject("ATTACHMENT_LENGTH_INVALID", "invalid declared file size")
            declared = int(lengths[0])
            if declared > max_bytes:
                raise _reject("ATTACHMENT_SIZE_LIMIT", "file exceeds max_structured_file_bytes")
        payload = bytearray()
        digest = hashlib.sha256()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            if connection.sock is not None:
                connection.sock.settimeout(min(10, remaining))
            # read1 returns after one underlying read so a trickling body cannot keep
            # resetting the total body deadline. Read at most one excess byte.
            chunk = response.read1(min(64 * 1024, max_bytes - len(payload) + 1))
            if not chunk:
                break
            if len(payload) + len(chunk) > max_bytes:
                raise _reject("ATTACHMENT_SIZE_LIMIT", "file exceeds max_structured_file_bytes")
            digest.update(chunk)
            payload.extend(chunk)
        if time.monotonic() >= deadline:
            raise TimeoutError
        if declared is not None and len(payload) != declared:
            raise _reject("ATTACHMENT_INCOMPLETE", "downloaded size differs from declared size")
        actual_sha256 = digest.hexdigest()
        if expected_sha256 is not None and actual_sha256 != expected_sha256:
            raise _reject("ATTACHMENT_SHA256_MISMATCH", "downloaded file SHA-256 does not match")
        data = bytes(payload)
        detected = _detect_media_type(data)
        supplied = file.get("mime_type", "").split(";", 1)[0].lower()
        # Reject contradictions for signatures we can recognize; other types stay opaque.
        if (
            supplied in {"image/jpeg", "image/png", "image/gif", "image/webp", "application/pdf"}
            and supplied != detected
        ):
            raise _reject(
                "ATTACHMENT_FORMAT_MISMATCH", "file signature does not match supplied type"
            )
        return DownloadedAttachment(data, actual_sha256, detected)
    except ArtifactTransferError:
        raise
    except TimeoutError:
        raise _reject("ATTACHMENT_TIMEOUT", "file retrieval timed out") from None
    except (OSError, http.client.HTTPException, ValueError):
        # Raw network exceptions can contain the bearer URL or local endpoint details.
        raise _reject(
            "ATTACHMENT_FETCH_FAILED", "file retrieval failed or was interrupted"
        ) from None
    finally:
        if timer is not None:
            timer.cancel()
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()
