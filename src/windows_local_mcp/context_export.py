from __future__ import annotations

import http.client
import ipaddress
import math
import os
import ssl
import stat
import tomllib
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from .control_plane_guard import assert_control_plane_healthy
from .redaction import redact_text
from .tool_safety import capture_file_identity, hold_file_identity, verify_file_identity
from .util import canonical_json, sha256_bytes, sha256_text, utc_now_iso

_CONTEXT_EXPORT_CONFIG_ENV = "LOCAL_MCP_CONTEXT_EXPORT_CONFIG"
_CONTEXT_EXPORT_SIDECAR = "context-export.toml"
_CONTEXT_EXPORT_CONFIG_MAX_BYTES = 64 * 1024
_CONTEXT_EXPORT_SCHEMA_VERSION = 1
_METADATA_MAX_DEPTH = 4
_METADATA_MAX_ENTRIES = 64
_METADATA_MAX_STRING_CHARACTERS = 4096
_METADATA_KEY_MAX_CHARACTERS = 128
_MAX_TAGS = 32
_MAX_TAG_CHARACTERS = 128
_MAX_KIND_CHARACTERS = 64
_MAX_TITLE_CHARACTERS = 512
_MAX_IDEMPOTENCY_KEY_CHARACTERS = 128
_MAX_BEARER_TOKEN_CHARACTERS = 8192

READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
EXTERNAL_WRITE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)


class ContextExportSettings(BaseModel):
    """Fail-closed settings for the optional Context Export sidecar."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    context_export_enabled: bool = False
    context_export_endpoint: str | None = None
    context_export_bearer_token: SecretStr | None = None
    context_export_max_bytes: int = Field(
        default=256 * 1024,
        ge=4096,
        le=4 * 1024 * 1024,
    )
    context_export_timeout_seconds: int = Field(default=10, ge=1, le=60)
    context_export_allow_insecure_http: bool = False

    @field_validator("context_export_endpoint", mode="before")
    @classmethod
    def normalize_endpoint(cls, value: object) -> str | None:
        if value is None or not str(value).strip():
            return None
        endpoint = str(value)
        if endpoint != endpoint.strip():
            raise ValueError("context_export_endpoint must not have surrounding whitespace")
        return endpoint

    @field_validator("context_export_bearer_token")
    @classmethod
    def validate_bearer_token(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None or not value.get_secret_value():
            return None
        token = value.get_secret_value()
        if len(token) > _MAX_BEARER_TOKEN_CHARACTERS:
            raise ValueError("context export bearer token is too long")
        try:
            token.encode("ascii")
        except UnicodeEncodeError as error:
            raise ValueError("context export bearer token must be ASCII") from error
        if any(
            character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
            for character in token
        ):
            raise ValueError(
                "context export bearer token contains unsafe whitespace/control characters"
            )
        return value

    @model_validator(mode="after")
    def validate_export_policy(self) -> ContextExportSettings:
        endpoint = self.context_export_endpoint
        if self.context_export_enabled and endpoint is None:
            raise ValueError(
                "context_export_endpoint is required when context_export_enabled=true"
            )
        if endpoint is not None:
            _validated_endpoint(
                endpoint,
                allow_insecure_http=self.context_export_allow_insecure_http,
            )
        return self


@dataclass(frozen=True)
class LoadedContextExportConfig:
    settings: ContextExportSettings
    selection_source: str
    config_selector_path: Path | None
    config_path: Path | None
    config_identity: dict[str, Any] | None


@dataclass(frozen=True)
class ValidatedEndpoint:
    url: str
    parts: SplitResult
    host: str
    port: int | None

    @property
    def request_target(self) -> str:
        return urlunsplit(("", "", self.parts.path or "/", self.parts.query, ""))

    def audit_summary(self) -> dict[str, Any]:
        return {
            "scheme": self.parts.scheme,
            "host": self.host,
            "port": self.port,
            "endpoint_sha256": sha256_text(self.url),
        }


def _contains_control(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _is_loopback_host(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validated_endpoint(value: str, *, allow_insecure_http: bool) -> ValidatedEndpoint:
    if not value or value != value.strip() or _contains_control(value) or "\\" in value:
        raise ValueError("context export endpoint contains unsafe characters")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError(
            "context export endpoint must be ASCII; percent-encode non-ASCII path data"
        ) from error
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as error:
        raise ValueError("context export endpoint is malformed") from error

    scheme = parts.scheme.casefold()
    if scheme not in {"http", "https"}:
        raise ValueError("context export endpoint must use http or https")
    if not parts.hostname:
        raise ValueError("context export endpoint must include a host")
    if parts.username is not None or parts.password is not None:
        raise ValueError("context export endpoint must not contain URL credentials")
    if parts.fragment:
        raise ValueError("context export endpoint must not contain a fragment")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("context export endpoint port is out of range")

    host = parts.hostname.casefold()
    if scheme == "http" and not _is_loopback_host(host) and not allow_insecure_http:
        raise ValueError(
            "non-loopback plain HTTP requires context_export_allow_insecure_http=true"
        )

    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    normalized = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return ValidatedEndpoint(
        url=normalized,
        parts=urlsplit(normalized),
        host=host,
        port=port,
    )


def _is_reparse(path: Path) -> bool:
    details = path.lstat()
    attributes = int(getattr(details, "st_file_attributes", 0))
    return path.is_symlink() or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _explicit_or_sidecar_config_path() -> tuple[Path | None, str]:
    explicit = os.environ.get(_CONTEXT_EXPORT_CONFIG_ENV, "").strip()
    if explicit:
        return Path(explicit).expanduser().absolute(), _CONTEXT_EXPORT_CONFIG_ENV

    main_config = os.environ.get("LOCAL_MCP_CONFIG", "").strip()
    if not main_config:
        return None, "not_configured"
    candidate = Path(main_config).expanduser().absolute().parent / _CONTEXT_EXPORT_SIDECAR
    if candidate.exists():
        return candidate, f"{_CONTEXT_EXPORT_SIDECAR}_beside_LOCAL_MCP_CONFIG"
    return None, "not_configured"


def load_context_export_config() -> LoadedContextExportConfig:
    selector, selection_source = _explicit_or_sidecar_config_path()
    if selector is None:
        return LoadedContextExportConfig(
            settings=ContextExportSettings(),
            selection_source=selection_source,
            config_selector_path=None,
            config_path=None,
            config_identity=None,
        )
    if _is_reparse(selector):
        raise ValueError("context export config must not be a symlink or reparse point")

    resolved = selector.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("context export config must be a regular file")
    identity = capture_file_identity(resolved, provenance="context-export-config")
    if int(identity.get("size", 0)) > _CONTEXT_EXPORT_CONFIG_MAX_BYTES:
        raise ValueError("context export config file exceeds 64 KiB")

    with hold_file_identity(identity) as held_path:
        if selector.resolve(strict=True) != held_path:
            raise RuntimeError("context export config selector changed during load")
        try:
            with held_path.open("rb") as source:
                payload = tomllib.load(source)
        except tomllib.TOMLDecodeError:
            raise ValueError("context export config TOML is invalid") from None
        if selector.resolve(strict=True) != held_path:
            raise RuntimeError("context export config selector changed during load")

    return LoadedContextExportConfig(
        settings=ContextExportSettings.model_validate(payload),
        selection_source=selection_source,
        config_selector_path=selector,
        config_path=resolved,
        config_identity=identity,
    )


def _is_inside(candidate: Path, root: Path) -> bool:
    try:
        candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
        return True
    except ValueError:
        return False


def validate_context_export_config_location(
    loaded: LoadedContextExportConfig,
    runtime_settings: Any,
) -> None:
    if loaded.config_path is None:
        return
    protected = (
        ("workspace_root", runtime_settings.workspace_root),
        ("data_dir", runtime_settings.data_dir),
        ("sandbox_scratch_dir", runtime_settings.sandbox_scratch_dir),
    )
    for label, root in protected:
        if root is not None and _is_inside(loaded.config_path, root):
            raise ValueError(f"context export config must be outside {label}")


def _verify_active_config(loaded: LoadedContextExportConfig) -> None:
    if loaded.config_identity is None:
        return
    selector = loaded.config_selector_path
    expected_path = loaded.config_path
    if selector is None or expected_path is None:
        raise PermissionError("context export configuration binding is incomplete")
    try:
        if _is_reparse(selector) or selector.resolve(strict=True) != expected_path:
            raise PermissionError("context export configuration changed")
        verify_file_identity(loaded.config_identity)
    except (OSError, RuntimeError, ValueError):
        raise PermissionError(
            "context export configuration changed after startup; restart is required"
        ) from None


def _assert_export_boundary(loaded: LoadedContextExportConfig, runtime: Any) -> None:
    try:
        assert_control_plane_healthy(runtime.settings)
        _verify_active_config(loaded)
    except (OSError, RuntimeError, ValueError):
        raise PermissionError("context export security preflight failed") from None


def _normalize_short_text(
    value: str | None,
    *,
    label: str,
    maximum: int,
    required: bool = False,
) -> str | None:
    if value is None:
        if required:
            raise ValueError(f"{label} is required")
        return None
    if not isinstance(value, str):
        raise TypeError(f"{label} must be text")
    normalized = value.strip()
    if required and not normalized:
        raise ValueError(f"{label} must not be empty")
    if not required and not normalized:
        return None
    if len(normalized) > maximum or _contains_control(normalized):
        raise ValueError(f"{label} is invalid or exceeds its limit")
    return normalized


def _normalize_tags(tags: list[str] | None) -> list[str]:
    if tags is None:
        return []
    if len(tags) > _MAX_TAGS:
        raise ValueError("too many context export tags")
    result: list[str] = []
    seen: set[str] = set()
    for value in tags:
        tag = _normalize_short_text(
            value,
            label="tag",
            maximum=_MAX_TAG_CHARACTERS,
            required=True,
        )
        assert tag is not None
        if tag not in seen:
            seen.add(tag)
            result.append(tag)
    return result


def _normalize_metadata_value(
    value: Any,
    *,
    depth: int,
    counter: list[int],
) -> Any:
    if depth > _METADATA_MAX_DEPTH:
        raise ValueError("context export metadata depth limit exceeded")
    counter[0] += 1
    if counter[0] > _METADATA_MAX_ENTRIES:
        raise ValueError("context export metadata entry limit exceeded")

    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str) and len(value) > _METADATA_MAX_STRING_CHARACTERS:
            raise ValueError("context export metadata string is too long")
        return value
    if isinstance(value, int):
        if abs(value) > (2**63 - 1):
            raise ValueError("context export metadata integer is out of range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("context export metadata float must be finite")
        return value
    if isinstance(value, list):
        if len(value) > _METADATA_MAX_ENTRIES:
            raise ValueError("context export metadata list is too large")
        return [
            _normalize_metadata_value(item, depth=depth + 1, counter=counter)
            for item in value
        ]
    if isinstance(value, dict):
        if len(value) > _METADATA_MAX_ENTRIES:
            raise ValueError("context export metadata object is too large")
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("context export metadata keys must be text")
            normalized_key = _normalize_short_text(
                key,
                label="metadata key",
                maximum=_METADATA_KEY_MAX_CHARACTERS,
                required=True,
            )
            assert normalized_key is not None
            result[normalized_key] = _normalize_metadata_value(
                item,
                depth=depth + 1,
                counter=counter,
            )
        return result
    raise TypeError("context export metadata must contain JSON-compatible values only")


def _normalize_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    if metadata is None:
        return {}
    if not isinstance(metadata, dict):
        raise TypeError("context export metadata must be an object")
    normalized = _normalize_metadata_value(metadata, depth=0, counter=[0])
    assert isinstance(normalized, dict)
    return normalized


def _normalize_idempotency_key(value: str | None) -> str:
    if value is None or not value.strip():
        return f"wlmcp-{uuid.uuid4()}"
    normalized = value.strip()
    if len(normalized) > _MAX_IDEMPOTENCY_KEY_CHARACTERS:
        raise ValueError("idempotency_key is invalid or exceeds its limit")
    try:
        normalized.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("idempotency_key must be ASCII") from error
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in normalized):
        raise ValueError("idempotency_key contains unsafe characters")
    return normalized


class ContextExportBroker:
    def __init__(self, settings: ContextExportSettings) -> None:
        self.settings = settings

    def capability(self) -> dict[str, Any]:
        endpoint = self.settings.context_export_endpoint
        validated = (
            _validated_endpoint(
                endpoint,
                allow_insecure_http=self.settings.context_export_allow_insecure_http,
            )
            if endpoint is not None
            else None
        )
        return {
            "configured": endpoint is not None,
            "enabled": self.settings.context_export_enabled,
            "available": bool(
                self.settings.context_export_enabled and validated is not None
            ),
            "fixed_destination": True,
            "schema_version": _CONTEXT_EXPORT_SCHEMA_VERSION,
            "endpoint": validated.audit_summary() if validated is not None else None,
            "bearer_auth_configured": self.settings.context_export_bearer_token is not None,
            "max_bytes": self.settings.context_export_max_bytes,
            "timeout_seconds": self.settings.context_export_timeout_seconds,
            "allow_insecure_http": self.settings.context_export_allow_insecure_http,
            "redirects_followed": False,
            "ambient_proxy_used": False,
            "response_body_returned": False,
        }

    def export(
        self,
        *,
        content: str,
        kind: str,
        title: str | None,
        tags: list[str] | None,
        metadata: dict[str, Any] | None,
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

        endpoint = _validated_endpoint(
            endpoint_value,
            allow_insecure_http=self.settings.context_export_allow_insecure_http,
        )
        normalized_kind = _normalize_short_text(
            kind,
            label="kind",
            maximum=_MAX_KIND_CHARACTERS,
            required=True,
        )
        assert normalized_kind is not None
        normalized_title = _normalize_short_text(
            title,
            label="title",
            maximum=_MAX_TITLE_CHARACTERS,
        )
        normalized_tags = _normalize_tags(tags)
        normalized_metadata = _normalize_metadata(metadata)
        normalized_idempotency_key = _normalize_idempotency_key(idempotency_key)
        export_id = str(uuid.uuid4())
        payload = {
            "schema_version": _CONTEXT_EXPORT_SCHEMA_VERSION,
            "export_id": export_id,
            "idempotency_key": normalized_idempotency_key,
            "created_at": utc_now_iso(),
            "source": {
                "transport": "windows-local-mcp",
                "trust": "model_supplied",
            },
            "context": {
                "kind": normalized_kind,
                "title": normalized_title,
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
            "User-Agent": "WindowsLocalMCP-ContextExport/1",
            "X-WLMCP-Export-ID": export_id,
        }
        token = self.settings.context_export_bearer_token
        if token is not None:
            headers["Authorization"] = f"Bearer {token.get_secret_value()}"

        status = self._post(endpoint, body, headers)
        receipt = {
            "export_id": export_id,
            "idempotency_key": normalized_idempotency_key,
            "schema_version": _CONTEXT_EXPORT_SCHEMA_VERSION,
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
            "title_sha256": (
                sha256_text(normalized_title) if normalized_title is not None else None
            ),
        }
        return receipt, audit_details

    def _post(
        self,
        endpoint: ValidatedEndpoint,
        body: bytes,
        headers: dict[str, str],
    ) -> int:
        connection_class = (
            http.client.HTTPSConnection
            if endpoint.parts.scheme == "https"
            else http.client.HTTPConnection
        )
        kwargs: dict[str, Any] = {
            "host": endpoint.host,
            "port": endpoint.port,
            "timeout": self.settings.context_export_timeout_seconds,
        }
        if connection_class is http.client.HTTPSConnection:
            kwargs["context"] = ssl.create_default_context()
        connection = connection_class(**kwargs)
        try:
            connection.request(
                "POST",
                endpoint.request_target,
                body=body,
                headers=headers,
            )
            response = connection.getresponse()
            status = int(response.status)
        except (OSError, http.client.HTTPException):
            raise RuntimeError("context export transport failed") from None
        finally:
            connection.close()

        if not 200 <= status < 300:
            raise RuntimeError(f"context export receiver returned HTTP {status}")
        return status


def _audit_request_summary(
    *,
    content: str,
    kind: str,
    title: str | None,
    tags: list[str] | None,
    metadata: dict[str, Any] | None,
    idempotency_key: str | None,
) -> dict[str, Any]:
    return {
        "kind": redact_text(kind)[:_MAX_KIND_CHARACTERS],
        "title": (
            {"characters": len(title), "sha256": sha256_text(title)}
            if title is not None
            else None
        ),
        "content": {
            "bytes": len(content.encode(errors="replace")),
            "sha256": sha256_text(content),
        },
        "tags": {
            "count": len(tags or []),
            "sha256": sha256_text(canonical_json(tags or [])),
        },
        "metadata": {
            "sha256": sha256_text(canonical_json(metadata or {})),
        },
        "idempotency_key_sha256": (
            sha256_text(idempotency_key) if idempotency_key else None
        ),
        "idempotency_key_generated": not bool(idempotency_key),
    }


def _start_audit(runtime: Any, request: dict[str, Any]) -> str:
    return runtime.audit.create_operation(
        tool_name="export_context",
        tier="broker",
        status="running",
        cwd=str(runtime.settings.workspace_root),
        request=request,
    )


def _finish_audit_success(
    runtime: Any,
    operation_id: str,
    *,
    receipt: dict[str, Any],
    audit_details: dict[str, Any],
) -> None:
    audit_receipt = {
        key: value
        for key, value in receipt.items()
        if key != "idempotency_key"
    }
    audit_receipt["idempotency_key_sha256"] = sha256_text(
        str(receipt["idempotency_key"])
    )
    result = {"receipt": audit_receipt, **audit_details}
    runtime.audit.update_operation(
        operation_id,
        status="succeeded",
        result_json=canonical_json(result),
        finished_at=utc_now_iso(),
    )
    runtime.audit.add_event(operation_id, "succeeded", result)


def _finish_audit_failure(runtime: Any, operation_id: str, error: Exception) -> None:
    rejected = isinstance(error, (PermissionError, ValueError, TypeError))
    status = "rejected" if rejected else "failed"
    runtime.audit.update_operation(
        operation_id,
        status=status,
        error=redact_text(f"{type(error).__name__}: {error}")[:1000],
        finished_at=utc_now_iso(),
    )
    runtime.audit.add_event(
        operation_id,
        status,
        {"error_type": type(error).__name__},
    )


def register_context_export_tools(
    mcp: MCPServer,
    loaded: LoadedContextExportConfig,
    runtime: Any,
) -> None:
    """Register the optional Context Export surface on the production MCP server."""

    validate_context_export_config_location(loaded, runtime.settings)
    broker = ContextExportBroker(loaded.settings)

    @mcp.tool(annotations=READ_ONLY)
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
            _assert_export_boundary(loaded, runtime)
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

    @mcp.tool(annotations=EXTERNAL_WRITE)
    def export_context(
        content: str,
        kind: str = "context",
        title: str | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Export bounded model-supplied context to the operator-configured fixed endpoint."""
        request = _audit_request_summary(
            content=content,
            kind=kind,
            title=title,
            tags=tags,
            metadata=metadata,
            idempotency_key=idempotency_key,
        )
        operation_id = _start_audit(runtime, request)
        try:
            _assert_export_boundary(loaded, runtime)
            receipt, audit_details = broker.export(
                content=content,
                kind=kind,
                title=title,
                tags=tags,
                metadata=metadata,
                idempotency_key=idempotency_key,
            )
        except Exception as error:
            _finish_audit_failure(runtime, operation_id, error)
            raise
        _finish_audit_success(
            runtime,
            operation_id,
            receipt=receipt,
            audit_details=audit_details,
        )
        receipt["operation_id"] = operation_id
        return receipt
