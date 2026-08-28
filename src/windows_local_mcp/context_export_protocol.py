from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from mcp.server import MCPServer

from . import context_export as core
from .redaction import redact_text
from .util import canonical_json, sha256_bytes, sha256_text, utc_now_iso

CONTEXT_EXPORT_SCHEMA_VERSION = 2
_MAX_SCOPE_CHARACTERS = 256
_MAX_OBSERVED_AT_CHARACTERS = 64
_CONTENT_FORMATS = {"plain_text", "markdown"}


def _normalize_content_format(value: str | None) -> str:
    normalized = core._normalize_short_text(
        value or "plain_text",
        label="content_format",
        maximum=32,
        required=True,
    )
    assert normalized is not None
    if normalized not in _CONTENT_FORMATS:
        raise ValueError("content_format must be plain_text or markdown")
    return normalized


def _normalize_observed_at(value: str | None) -> str | None:
    normalized = core._normalize_short_text(
        value,
        label="observed_at",
        maximum=_MAX_OBSERVED_AT_CHARACTERS,
    )
    if normalized is None:
        return None
    parse_value = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    try:
        parsed = datetime.fromisoformat(parse_value)
    except ValueError as error:
        raise ValueError("observed_at must be a valid ISO 8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("observed_at must include an explicit timezone offset")
    return normalized


def _audit_request_summary(
    *,
    content: str,
    kind: str,
    scope: str | None,
    title: str | None,
    content_format: str,
    tags: list[str] | None,
    metadata: dict[str, Any] | None,
    observed_at: str | None,
    idempotency_key: str | None,
) -> dict[str, Any]:
    return {
        "kind": redact_text(kind)[: core._MAX_KIND_CHARACTERS],
        "scope": (
            {"characters": len(scope), "sha256": sha256_text(scope)}
            if scope is not None
            else None
        ),
        "title": (
            {"characters": len(title), "sha256": sha256_text(title)}
            if title is not None
            else None
        ),
        "content_format": content_format,
        "observed_at_sha256": sha256_text(observed_at) if observed_at else None,
        "content": {
            "bytes": len(content.encode(errors="replace")),
            "sha256": sha256_text(content),
        },
        "tags": {
            "count": len(tags or []),
            "sha256": sha256_text(canonical_json(tags or [])),
        },
        "metadata": {"sha256": sha256_text(canonical_json(metadata or {}))},
        "idempotency_key_sha256": (
            sha256_text(idempotency_key) if idempotency_key else None
        ),
        "idempotency_key_generated": not bool(idempotency_key),
    }


class ContextExportBroker(core.ContextExportBroker):
    def capability(self) -> dict[str, Any]:
        result = super().capability()
        result["schema_version"] = CONTEXT_EXPORT_SCHEMA_VERSION
        return result

    def export(
        self,
        *,
        content: str,
        kind: str,
        scope: str | None,
        title: str | None,
        content_format: str,
        tags: list[str] | None,
        metadata: dict[str, Any] | None,
        observed_at: str | None,
        idempotency_key: str | None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if not self.settings.context_export_enabled:
            raise PermissionError("context export capability is disabled")
        endpoint_value = self.settings.context_export_endpoint
        if endpoint_value is None:
            raise PermissionError("context export endpoint is not configured")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("context export content must be non-empty text")
        if len(content.encode()) > self.settings.context_export_max_bytes:
            raise ValueError("context export content exceeds configured byte limit")

        endpoint = core._validated_endpoint(
            endpoint_value,
            allow_insecure_http=self.settings.context_export_allow_insecure_http,
        )
        normalized_kind = core._normalize_short_text(
            kind,
            label="kind",
            maximum=core._MAX_KIND_CHARACTERS,
            required=True,
        )
        assert normalized_kind is not None
        normalized_scope = core._normalize_short_text(
            scope,
            label="scope",
            maximum=_MAX_SCOPE_CHARACTERS,
        )
        normalized_title = core._normalize_short_text(
            title,
            label="title",
            maximum=core._MAX_TITLE_CHARACTERS,
        )
        normalized_content_format = _normalize_content_format(content_format)
        normalized_observed_at = _normalize_observed_at(observed_at)
        normalized_tags = core._normalize_tags(tags)
        normalized_metadata = core._normalize_metadata(metadata)
        normalized_idempotency_key = core._normalize_idempotency_key(idempotency_key)
        export_id = str(uuid.uuid4())
        payload = {
            "schema_version": CONTEXT_EXPORT_SCHEMA_VERSION,
            "export_id": export_id,
            "idempotency_key": normalized_idempotency_key,
            "created_at": utc_now_iso(),
            "source": {
                "transport": "windows-local-mcp",
                "trust": "model_supplied",
            },
            "context": {
                "kind": normalized_kind,
                "scope": normalized_scope,
                "title": normalized_title,
                "content_format": normalized_content_format,
                "observed_at": normalized_observed_at,
                "content": content,
                "tags": normalized_tags,
                "metadata": normalized_metadata,
            },
        }
        body = canonical_json(payload).encode()
        if len(body) > self.settings.context_export_max_bytes:
            raise ValueError("serialized context export payload exceeds configured byte limit")

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "Idempotency-Key": normalized_idempotency_key,
            "User-Agent": "WindowsLocalMCP-ContextExport/2",
            "X-WLMCP-Export-ID": export_id,
        }
        token = self.settings.context_export_bearer_token
        if token is not None:
            headers["Authorization"] = f"Bearer {token.get_secret_value()}"

        status = self._post(endpoint, body, headers)
        receipt = {
            "export_id": export_id,
            "idempotency_key": normalized_idempotency_key,
            "schema_version": CONTEXT_EXPORT_SCHEMA_VERSION,
            "http_status": status,
            "payload_bytes": len(body),
            "content_bytes": len(content.encode()),
            "content_sha256": sha256_text(content),
        }
        audit_details = {
            "endpoint": endpoint.audit_summary(),
            "payload_bytes": len(body),
            "payload_sha256": sha256_bytes(body),
            "metadata_sha256": sha256_text(canonical_json(normalized_metadata)),
            "tags_sha256": sha256_text(canonical_json(normalized_tags)),
            "scope_sha256": (
                sha256_text(normalized_scope) if normalized_scope is not None else None
            ),
            "content_format": normalized_content_format,
            "observed_at_sha256": (
                sha256_text(normalized_observed_at)
                if normalized_observed_at is not None
                else None
            ),
            "title_sha256": (
                sha256_text(normalized_title) if normalized_title is not None else None
            ),
        }
        return receipt, audit_details


def register_context_export_tools(
    mcp: MCPServer,
    loaded: core.LoadedContextExportConfig,
    runtime: Any,
) -> None:
    """Register Context Export protocol v2 on the production MCP server."""

    core.validate_context_export_config_location(loaded, runtime.settings)
    broker = ContextExportBroker(loaded.settings)

    @mcp.tool(annotations=core.READ_ONLY)
    def context_export_info() -> dict[str, Any]:
        """Show bounded Context Export capability status without exposing credentials."""
        result = broker.capability()
        result["selection_source"] = loaded.selection_source
        result["config_sha256"] = (
            str(loaded.config_identity.get("sha256"))
            if loaded.config_identity is not None
            else None
        )
        try:
            core._assert_export_boundary(loaded, runtime)
        except PermissionError:
            result["available"] = False
            result["security_preflight"] = "failed"
        else:
            result["security_preflight"] = "verified"

        operation_id = runtime.audit.create_operation(
            tool_name="context_export_info",
            tier="read",
            status="succeeded",
            cwd=str(runtime.settings.workspace_root),
            request={},
        )
        runtime.audit.update_operation(
            operation_id,
            result_json=canonical_json(result),
            finished_at=utc_now_iso(),
        )
        runtime.audit.add_event(operation_id, "succeeded", result)
        result["operation_id"] = operation_id
        return result

    @mcp.tool(annotations=core.EXTERNAL_WRITE)
    def export_context(
        content: str,
        kind: str = "context",
        scope: str | None = None,
        title: str | None = None,
        content_format: str = "plain_text",
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        observed_at: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Export bounded model-supplied context to the configured fixed endpoint."""
        request = _audit_request_summary(
            content=content,
            kind=kind,
            scope=scope,
            title=title,
            content_format=content_format,
            tags=tags,
            metadata=metadata,
            observed_at=observed_at,
            idempotency_key=idempotency_key,
        )
        operation_id = core._start_audit(runtime, request)
        try:
            core._assert_export_boundary(loaded, runtime)
            receipt, audit_details = broker.export(
                content=content,
                kind=kind,
                scope=scope,
                title=title,
                content_format=content_format,
                tags=tags,
                metadata=metadata,
                observed_at=observed_at,
                idempotency_key=idempotency_key,
            )
        except Exception as error:
            core._finish_audit_failure(runtime, operation_id, error)
            raise
        core._finish_audit_success(
            runtime,
            operation_id,
            receipt=receipt,
            audit_details=audit_details,
        )
        receipt["operation_id"] = operation_id
        return receipt
