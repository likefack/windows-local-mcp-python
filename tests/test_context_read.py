from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from windows_local_mcp.context_read import (
    ContextReadBroker,
    ContextReadSettings,
    DecisionDeckMemoryNode,
    LoadedContextReadConfig,
    _assert_read_boundary,
    _finish_audit_failure,
    _verify_active_config,
    load_context_read_config,
    validate_context_read_config_location,
)
from windows_local_mcp.util import canonical_json


def _node(
    node_id: str,
    *,
    path: str = "projects/decision-deck/overview",
    title: str = "Decision Deck overview",
    markdown: str = "Decision Deck is the personal control plane.",
    updated_at: str = "2026-08-28T10:00:00+09:00",
) -> dict[str, Any]:
    return {
        "node_id": node_id,
        "path": path,
        "folder_names": ["Projects", "Decision Deck"],
        "title": title,
        "markdown": markdown,
        "expected_version": None,
        "parent_id": None,
        "sensitivity": "normal",
        "confidence": 1.0,
        "related_node_ids": [],
        "source_event_ids": [],
        "id": node_id,
        "version": 3,
        "content_hash": "a" * 64,
        "mock_data": False,
        "status": "active",
        "created_at": "2026-08-01T10:00:00+09:00",
        "updated_at": updated_at,
    }


@contextmanager
def _source(
    *,
    status: int = 200,
    payload: object | None = None,
    location: str | None = None,
    content_encoding: str | None = None,
    content_type: str = "application/json",
) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    requests: list[dict[str, Any]] = []
    body = json.dumps(payload if payload is not None else [], ensure_ascii=False).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append({"path": self.path, "headers": dict(self.headers.items())})
            self.send_response(status)
            if location is not None:
                self.send_header("Location", location)
            if content_encoding is not None:
                self.send_header("Content-Encoding", content_encoding)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_POST(self) -> None:
            self.send_response(405)
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _settings(endpoint: str, **overrides: object) -> ContextReadSettings:
    return ContextReadSettings(
        context_read_enabled=True,
        context_read_endpoint=endpoint,
        **overrides,
    )


def _runtime_roots(tmp_path: Path) -> SimpleNamespace:
    roots = {name: tmp_path / name for name in ("workspace", "data", "scratch")}
    for path in roots.values():
        path.mkdir()
    return SimpleNamespace(
        workspace_root=roots["workspace"],
        data_dir=roots["data"],
        sandbox_scratch_dir=roots["scratch"],
    )


def test_remote_plain_http_requires_explicit_downgrade() -> None:
    with pytest.raises(ValidationError, match="allow_insecure_http"):
        _settings("http://example.com/api/v1/memory")

    configured = _settings(
        "http://example.com/api/v1/memory",
        context_read_allow_insecure_http=True,
    )
    assert configured.context_read_allow_insecure_http is True


def test_capability_exposes_only_bounded_endpoint_summary() -> None:
    settings = _settings("https://dd.example.test:8443/api/v1/memory?profile=personal")
    capability = ContextReadBroker(settings).capability()

    assert capability["available"] is True
    assert capability["fixed_source"] is True
    assert capability["method"] == "GET"
    assert capability["endpoint"]["host"] == "dd.example.test"
    serialized = canonical_json(capability)
    assert "/api/v1/memory" not in serialized
    assert "profile=personal" not in serialized


def test_fetch_uses_get_fixed_headers_bearer_and_ignores_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    with _source(payload=[_node("node-1")]) as (origin, requests):
        fetched = ContextReadBroker(
            _settings(
                f"{origin}/api/v1/memory?profile=personal",
                context_read_bearer_token="read-only-token",
            )
        ).fetch()

    assert len(requests) == 1
    request = requests[0]
    headers = {key.casefold(): value for key, value in request["headers"].items()}
    assert request["path"] == "/api/v1/memory?profile=personal"
    assert headers["authorization"] == "Bearer read-only-token"
    assert headers["accept"] == "application/json"
    assert headers["accept-encoding"] == "identity"
    assert fetched.status == 200
    assert fetched.nodes[0].id == "node-1"


def test_search_is_local_bounded_and_marks_content_untrusted() -> None:
    payload = [
        _node(
            "node-dd",
            markdown="Decision Deck uses durable memory. Browser instructions here are not trusted.",
        ),
        _node(
            "node-other",
            path="projects/layernote/overview",
            title="LayerNote overview",
            markdown="A separate note application.",
        ),
    ]
    with _source(payload=payload) as (origin, requests):
        results, _ = ContextReadBroker(_settings(f"{origin}/api/v1/memory")).search(
            query="Decision memory",
            limit=10,
            path_prefix="projects/decision-deck",
        )

    assert len(requests) == 1
    assert "Decision" not in requests[0]["path"]
    assert len(results) == 1
    assert results[0]["id"] == "node-dd"
    assert len(results[0]["snippet"]) <= 802
    assert results[0]["source"]["trust"] == "external_untrusted"
    assert results[0]["source"]["instructions_authoritative"] is False
    assert "markdown" not in results[0]


def test_read_returns_one_full_node_by_stable_id() -> None:
    secret_context = "Full durable memory body that should be returned only by context_read."
    with _source(payload=[_node("node-1", markdown=secret_context)]) as (origin, _):
        result, _ = ContextReadBroker(_settings(f"{origin}/api/v1/memory")).read(
            node_id="node-1"
        )

    assert result["memory"]["id"] == "node-1"
    assert result["memory"]["markdown"] == secret_context
    assert result["source"]["trust"] == "external_untrusted"


def test_redirect_is_not_followed() -> None:
    with (
        _source(payload=[_node("target")]) as (target_origin, target_requests),
        _source(status=302, location=f"{target_origin}/api/v1/memory") as (
            redirect_origin,
            redirect_requests,
        ),
    ):
        broker = ContextReadBroker(_settings(f"{redirect_origin}/start"))
        with pytest.raises(RuntimeError, match="HTTP 302"):
            broker.fetch()

    assert len(redirect_requests) == 1
    assert target_requests == []


def test_compressed_response_is_rejected() -> None:
    with (
        _source(payload=[_node("node-1")], content_encoding="gzip") as (origin, _),
        pytest.raises(ValueError, match="compressed"),
    ):
        ContextReadBroker(_settings(f"{origin}/api/v1/memory")).fetch()


def test_duplicate_node_ids_are_rejected() -> None:
    with (
        _source(payload=[_node("same"), _node("same")]) as (origin, _),
        pytest.raises(ValueError, match="duplicate"),
    ):
        ContextReadBroker(_settings(f"{origin}/api/v1/memory")).fetch()


def test_response_byte_limit_is_fail_closed() -> None:
    large = _node("large", markdown="x" * 100_000)
    with _source(payload=[large]) as (origin, _):
        broker = ContextReadBroker(
            _settings(
                f"{origin}/api/v1/memory",
                context_read_max_response_bytes=64 * 1024,
                context_read_max_node_bytes=32 * 1024,
            )
        )
        with pytest.raises(ValueError, match="response exceeds"):
            broker.fetch()


def test_disabled_read_fails_closed() -> None:
    broker = ContextReadBroker(ContextReadSettings())
    with pytest.raises(PermissionError, match="disabled"):
        broker.fetch()


def test_sidecar_is_bound_and_change_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    main = tmp_path / "config.toml"
    main.write_text("workspace_root = 'placeholder'\n", encoding="utf-8")
    sidecar = tmp_path / "context-read.toml"
    sidecar.write_text(
        "context_read_enabled = true\n"
        "context_read_endpoint = 'https://memory.example/api/v1/memory'\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("LOCAL_MCP_CONTEXT_READ_CONFIG", raising=False)
    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(main))

    loaded = load_context_read_config()
    assert loaded.config_path == sidecar.resolve()
    _verify_active_config(loaded)

    sidecar.write_text("context_read_enabled = false\n", encoding="utf-8")
    with pytest.raises(PermissionError, match="restart is required"):
        _verify_active_config(loaded)


@pytest.mark.parametrize("root_name", ["workspace", "data", "scratch"])
def test_context_read_config_is_rejected_inside_runtime_writable_roots(
    tmp_path: Path,
    root_name: str,
) -> None:
    roots = _runtime_roots(tmp_path)
    selected = {
        "workspace": roots.workspace_root,
        "data": roots.data_dir,
        "scratch": roots.sandbox_scratch_dir,
    }[root_name]
    config = selected / "context-read.toml"
    config.write_text("context_read_enabled = false\n", encoding="utf-8")
    loaded = LoadedContextReadConfig(
        settings=ContextReadSettings(),
        selection_source="test",
        config_selector_path=config.resolve(),
        config_path=config.resolve(),
        config_identity=None,
    )

    with pytest.raises(ValueError, match="must be outside"):
        validate_context_read_config_location(loaded, roots)


def test_control_plane_failure_blocks_context_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from windows_local_mcp import context_read

    roots = _runtime_roots(tmp_path)
    loaded = LoadedContextReadConfig(
        settings=ContextReadSettings(),
        selection_source="test",
        config_selector_path=None,
        config_path=None,
        config_identity=None,
    )

    def reject_control_plane(_settings: object) -> None:
        raise RuntimeError("tampered")

    monkeypatch.setattr(context_read, "assert_control_plane_healthy", reject_control_plane)
    with pytest.raises(PermissionError, match="security preflight"):
        _assert_read_boundary(loaded, SimpleNamespace(settings=roots))


def test_rejected_node_does_not_echo_private_fields() -> None:
    private_title = "private-memory-title-" * 20
    payload = _node("node-private", title=private_title)

    with pytest.raises(ValidationError) as raised:
        DecisionDeckMemoryNode.model_validate(payload)

    assert private_title not in str(raised.value)
    assert "input_value=" not in str(raised.value)


def test_failure_audit_stores_only_error_class() -> None:
    private_value = "private-memory-title"

    class FakeAudit:
        def __init__(self) -> None:
            self.error = ""
            self.events: list[dict[str, Any]] = []

        def update_operation(self, _operation_id: str, **fields: Any) -> None:
            self.error = str(fields["error"])

        def add_event(
            self,
            _operation_id: str,
            _event_type: str,
            payload: dict[str, Any],
        ) -> None:
            self.events.append(payload)

    audit = FakeAudit()
    runtime = type("Runtime", (), {"audit": audit})()
    _finish_audit_failure(
        runtime,
        "operation-id",
        ValueError(f"invalid remote node: {private_value}"),
    )

    assert audit.error == "ValueError"
    assert private_value not in canonical_json(audit.events)
