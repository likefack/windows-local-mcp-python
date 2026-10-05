"""Network-policy tests use synthetic responses, never a real temporary file URL."""

import hashlib
import http.client
import io
import socket
import ssl
from email.message import Message

import pytest
from PIL import Image

from windows_local_mcp import attachment_import as subject
from windows_local_mcp.artifact_errors import ArtifactTransferError

HOST = "files.example.com"
REFERENCE = {"file_id": "file_test", "download_url": f"https://{HOST}/input?secret=temporary"}
PUBLIC = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]


class Response:
    def __init__(
        self, payload, *, status=200, headers=(("Transfer-Encoding", "chunked"),), fail=False
    ):
        self.status = status
        self.headers = Message()
        for key, value in headers:
            self.headers[key] = value
        self.data = io.BytesIO(payload)
        self.fail = fail
        self.read_sizes = []

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def close(self):
        self.closed = True

    def read1(self, count):
        self.read_sizes.append(count)
        if self.fail and self.data.tell():
            raise OSError(REFERENCE["download_url"])
        return self.data.read(min(count, 1024))


def install_network(monkeypatch, response):
    calls = []

    class Connection:
        sock = None

        def __init__(self, host, address, *, timeout):
            calls.append((host, address, timeout))
            self.closed = False
            calls.append(self)

        def request(self, method, target, *, headers):
            calls.append((method, target, headers))

        def getresponse(self):
            return response

        def close(self):
            self.closed = True

    monkeypatch.setattr(subject.socket, "getaddrinfo", lambda *a, **kw: PUBLIC)
    monkeypatch.setattr(subject, "_PinnedHTTPSConnection", Connection)
    return calls


def retrieve(**kwargs):
    return subject.download_attachment(REFERENCE, allowed_hosts=[HOST], max_bytes=500_000, **kwargs)


def test_real_jpeg_bytes_and_incremental_hash_are_preserved(monkeypatch):
    stream = io.BytesIO()
    # A deterministic noisy JPEG of several hundred KB; no model-produced Base64.
    raw = bytes((index * 31 + index // 613) % 256 for index in range(600 * 600 * 3))
    Image.frombytes("RGB", (600, 600), raw).save(stream, "JPEG", quality=92)
    payload = stream.getvalue()
    assert 200_000 < len(payload) < 500_000
    response = Response(payload, headers=[("Content-Length", str(len(payload)))])
    calls = install_network(monkeypatch, response)
    result = retrieve(expected_sha256=hashlib.sha256(payload).hexdigest())
    assert result.payload == payload
    assert result.sha256 == hashlib.sha256(payload).hexdigest()
    assert result.detected_mime_type == "image/jpeg"
    assert calls[0][1] == PUBLIC[0]
    assert calls[2] == ("GET", "/input?secret=temporary", {"Accept-Encoding": "identity"})
    assert calls[1].closed


@pytest.mark.parametrize(
    "url",
    [
        "http://files.example.com/input",
        "https://files.example.com:444/input",
        "https://files.example.com.evil.test/input",
        "https://files.example.com@evil.test/input",
        "https://evil.test@files.example.com/input",
        "https://files.example.com./input",
        "https://files.example.com/input#fragment",
        "https://127.0.0.1/input",
        "https://[::1]/input",
        "file:///C:/secret",
        "https://files.example.com\\@evil.test/input",
        "https://files.example.com/input\r\nX: header",
        "https://files.example.com/",
    ],
)
def test_invalid_reference_is_rejected_before_dns(monkeypatch, url):
    monkeypatch.setattr(subject.socket, "getaddrinfo", lambda *a, **k: pytest.fail("DNS reached"))
    with pytest.raises(ArtifactTransferError, match="ATTACHMENT_REFERENCE_REJECTED"):
        subject.download_attachment(
            {**REFERENCE, "download_url": url}, allowed_hosts=[HOST], max_bytes=10
        )


@pytest.mark.parametrize(
    "file",
    [
        None,
        "temporary-secret",
        {},
        {**REFERENCE, "file_id": "bad/id"},
        {**REFERENCE, "file_name": None},
        {**REFERENCE, "unknown": "secret"},
    ],
)
def test_invalid_file_object_never_echoed(file):
    with pytest.raises(ArtifactTransferError) as caught:
        subject.validate_reference(file, [HOST])
    assert "temporary-secret" not in str(caught.value)
    assert "bad/id" not in str(caught.value)


def test_no_implicit_host_permission():
    with pytest.raises(ArtifactTransferError, match="ATTACHMENT_IMPORT_NOT_CONFIGURED"):
        subject.validate_reference(REFERENCE, [])


@pytest.mark.parametrize(
    "host",
    [
        "*.example.com",
        "https://files.example.com",
        "127.0.0.1",
        "files.example.com.",
        "Files.example.com",
        "a..example.com",
    ],
)
def test_configuration_rejects_patterns_urls_and_ip_literals(host):
    with pytest.raises(ValueError):
        subject.validate_allowed_hosts([host])


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.2",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "2002:7f00:1::",
    ],
)
def test_all_dns_answers_must_be_public(monkeypatch, ip):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    address = (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443)
    monkeypatch.setattr(
        subject.socket, "getaddrinfo", lambda *a, **kw: PUBLIC + [(family, 1, 6, "", address)]
    )
    monkeypatch.setattr(
        subject, "_PinnedHTTPSConnection", lambda *a, **kw: pytest.fail("connection reached")
    )
    with pytest.raises(ArtifactTransferError, match="ATTACHMENT_ADDRESS_REJECTED"):
        retrieve()


@pytest.mark.parametrize(
    ("status", "headers", "code"),
    [
        (302, [("Location", "http://127.0.0.1/secret")], "ATTACHMENT_REDIRECT_REJECTED"),
        (403, [], "ATTACHMENT_FETCH_FAILED"),
        (200, [("Content-Encoding", "gzip")], "ATTACHMENT_ENCODING_REJECTED"),
        (200, [("Content-Length", "500001")], "ATTACHMENT_SIZE_LIMIT"),
        (200, [("Content-Length", "-1")], "ATTACHMENT_LENGTH_INVALID"),
        (200, [("Content-Length", "1"), ("Content-Length", "1")], "ATTACHMENT_LENGTH_INVALID"),
        (
            200,
            [("Content-Length", "1"), ("Transfer-Encoding", "chunked")],
            "ATTACHMENT_LENGTH_INVALID",
        ),
        (200, [("Transfer-Encoding", "gzip")], "ATTACHMENT_LENGTH_INVALID"),
    ],
)
def test_headers_fail_without_reading_body(monkeypatch, status, headers, code):
    response = Response(b"data", status=status, headers=headers)
    calls = install_network(monkeypatch, response)
    with pytest.raises(ArtifactTransferError, match=code):
        retrieve()
    assert response.read_sizes == []
    assert calls[1].closed


def test_actual_size_bound_without_content_length(monkeypatch):
    response = Response(b"x" * 2048)
    install_network(monkeypatch, response)
    with pytest.raises(ArtifactTransferError, match="ATTACHMENT_SIZE_LIMIT"):
        subject.download_attachment(REFERENCE, allowed_hosts=[HOST], max_bytes=1024)
    assert response.data.tell() == 1025
    assert max(response.read_sizes) == 1025


def test_truncated_content_length(monkeypatch):
    install_network(monkeypatch, Response(b"short", headers=[("Content-Length", "20")]))
    with pytest.raises(ArtifactTransferError, match="ATTACHMENT_INCOMPLETE"):
        retrieve()


def test_unframed_response_requires_independent_source_hash(monkeypatch):
    response = Response(b"could be truncated", headers=[])
    install_network(monkeypatch, response)
    with pytest.raises(ArtifactTransferError, match="ATTACHMENT_LENGTH_REQUIRED"):
        retrieve()
    assert response.read_sizes == []


@pytest.mark.parametrize("body, succeeds", [(b"3\r\nabc\r\n0\r\n\r\n", True), (b"3\r\nab", False)])
def test_real_http_chunk_parser_requires_complete_chunked_body(monkeypatch, body, succeeds):
    class WireSocket:
        def makefile(self, *args):
            return io.BytesIO(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body)

    response = http.client.HTTPResponse(WireSocket())
    response.begin()
    install_network(monkeypatch, response)
    if succeeds:
        assert retrieve().payload == b"abc"
    else:
        with pytest.raises(ArtifactTransferError, match="ATTACHMENT_FETCH_FAILED"):
            retrieve()


def test_deadline_interrupts_detached_response_socket():
    class Socket:
        stopped = False

        def shutdown(self, how):
            assert how == socket.SHUT_RDWR
            self.stopped = True

    class Connection:
        sock = None  # HTTPConnection has handed its socket to HTTPResponse.
        active_socket = Socket()

    connection = Connection()
    subject._interrupt_connection(connection)
    assert connection.active_socket.stopped


def test_interrupted_download_does_not_expose_url(monkeypatch):
    calls = install_network(monkeypatch, Response(b"x" * 10000, fail=True))
    with pytest.raises(ArtifactTransferError, match="ATTACHMENT_FETCH_FAILED") as caught:
        retrieve()
    assert "temporary" not in str(caught.value)
    assert caught.value.__suppress_context__
    assert calls[1].closed


def test_hash_mismatch(monkeypatch):
    install_network(monkeypatch, Response(b"input"))
    with pytest.raises(ArtifactTransferError, match="ATTACHMENT_SHA256_MISMATCH"):
        retrieve(expected_sha256="0" * 64)


def test_mime_signature_mismatch(monkeypatch):
    install_network(monkeypatch, Response(b"not a jpeg"))
    with pytest.raises(ArtifactTransferError, match="ATTACHMENT_FORMAT_MISMATCH"):
        subject.download_attachment(
            {**REFERENCE, "mime_type": "image/jpeg"}, allowed_hosts=[HOST], max_bytes=100
        )


def test_filename_is_not_used_as_path_or_request(monkeypatch):
    calls = install_network(monkeypatch, Response(b"opaque data"))
    result = subject.download_attachment(
        {**REFERENCE, "file_name": "../../outside.exe"}, allowed_hosts=[HOST], max_bytes=100
    )
    assert result.payload == b"opaque data"
    assert "outside" not in repr(calls)


def test_connection_uses_checked_numeric_address_and_original_tls_name(monkeypatch):
    seen = []

    class Socket:
        def settimeout(self, timeout):
            seen.append(("timeout", timeout))

        def connect(self, address):
            seen.append(("connect", address))

        def close(self):
            seen.append("closed")

    class Context:
        def wrap_socket(self, sock, *, server_hostname):
            seen.append(("tls", server_hostname))
            return sock

    connection = subject._PinnedHTTPSConnection(HOST, PUBLIC[0], timeout=5)
    assert connection._context.check_hostname
    assert connection._context.verify_mode == ssl.CERT_REQUIRED
    connection._context = Context()
    monkeypatch.setattr(subject.socket, "socket", lambda *a: Socket())
    monkeypatch.setattr(
        subject.socket, "getaddrinfo", lambda *a, **kw: pytest.fail("second DNS lookup")
    )
    connection.connect()
    connection.close()
    assert ("connect", PUBLIC[0][4]) in seen
    assert ("tls", HOST) in seen
    assert "closed" in seen
