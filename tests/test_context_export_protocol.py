from __future__ import annotations

import json
from typing import Any

import pytest

from windows_local_mcp.context_export import ContextExportSettings
from windows_local_mcp.context_export_protocol import (
    CONTEXT_EXPORT_SCHEMA_VERSION,
    ContextExportBroker,
    _audit_request_summary,
)
from windows_local_mcp.util import canonical_json


def _broker() -> ContextExportBroker:
    return ContextExportBroker(
        ContextExportSettings(
            context_export_enabled=True,
            context_export_endpoint="https://receiver.example/import",
        )
    )


def test_protocol_v2_exports_semantic_context_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    broker = _broker()
    sent: dict[str, Any] = {}

    def fake_post(endpoint: Any, body: bytes, headers: dict[str, str]) -> int:
        sent["endpoint"] = endpoint
        sent["body"] = body
        sent["headers"] = headers
        return 200

    monkeypatch.setattr(broker, "_post", fake_post)
    receipt, audit = broker.export(
        content="# Current context\n\nRelevant details.",
        kind="conversation_summary",
        scope="project:decision-deck",
        title="Context handoff",
        content_format="markdown",
        tags=["chatgpt", "decision-deck"],
        metadata={"declared_source": "chatgpt_memory"},
        observed_at="2026-08-28T11:30:00+09:00",
        idempotency_key="context-v2-test",
    )

    payload = json.loads(sent["body"].decode())
    assert payload["schema_version"] == CONTEXT_EXPORT_SCHEMA_VERSION == 2
    assert payload["context"]["scope"] == "project:decision-deck"
    assert payload["context"]["content_format"] == "markdown"
    assert payload["context"]["observed_at"] == "2026-08-28T11:30:00+09:00"
    assert payload["source"]["trust"] == "model_supplied"
    assert sent["headers"]["User-Agent"] == "WindowsLocalMCP-ContextExport/2"
    assert receipt["schema_version"] == 2
    assert audit["content_format"] == "markdown"
    assert "project:decision-deck" not in canonical_json(audit)
    assert "2026-08-28T11:30:00+09:00" not in canonical_json(audit)


def test_protocol_v2_defaults_to_plain_text(monkeypatch: pytest.MonkeyPatch) -> None:
    broker = _broker()
    sent: dict[str, bytes] = {}

    def fake_post(_endpoint: Any, body: bytes, _headers: dict[str, str]) -> int:
        sent["body"] = body
        return 204

    monkeypatch.setattr(broker, "_post", fake_post)
    broker.export(
        content="context",
        kind="context",
        scope=None,
        title=None,
        content_format="plain_text",
        tags=None,
        metadata=None,
        observed_at=None,
        idempotency_key=None,
    )

    payload = json.loads(sent["body"].decode())
    assert payload["context"]["content_format"] == "plain_text"
    assert payload["context"]["scope"] is None
    assert payload["context"]["observed_at"] is None


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"content_format": "html"}, "content_format"),
        ({"observed_at": "2026-08-28T11:30:00"}, "timezone"),
        ({"observed_at": "not-a-time"}, "ISO 8601"),
        ({"scope": "x" * 257}, "scope"),
    ],
)
def test_protocol_v2_rejects_invalid_semantic_fields(
    monkeypatch: pytest.MonkeyPatch,
    kwargs: dict[str, str],
    match: str,
) -> None:
    broker = _broker()
    called = False

    def fake_post(_endpoint: Any, _body: bytes, _headers: dict[str, str]) -> int:
        nonlocal called
        called = True
        return 200

    monkeypatch.setattr(broker, "_post", fake_post)
    arguments: dict[str, Any] = {
        "content": "context",
        "kind": "context",
        "scope": None,
        "title": None,
        "content_format": "plain_text",
        "tags": None,
        "metadata": None,
        "observed_at": None,
        "idempotency_key": "invalid-field-test",
    }
    arguments.update(kwargs)

    with pytest.raises(ValueError, match=match):
        broker.export(**arguments)
    assert called is False


def test_protocol_v2_audit_summary_hashes_scope_and_observed_at() -> None:
    summary = _audit_request_summary(
        content="sensitive context",
        kind="memory",
        scope="project:private",
        title="private title",
        content_format="markdown",
        tags=["private"],
        metadata={"private": True},
        observed_at="2026-08-28T11:30:00+09:00",
        idempotency_key="private-retry-key",
    )
    serialized = canonical_json(summary)

    assert "sensitive context" not in serialized
    assert "project:private" not in serialized
    assert "private title" not in serialized
    assert "2026-08-28T11:30:00+09:00" not in serialized
    assert "private-retry-key" not in serialized
    assert summary["content_format"] == "markdown"


def test_protocol_v2_capability_reports_schema_2() -> None:
    capability = _broker().capability()
    assert capability["schema_version"] == 2
