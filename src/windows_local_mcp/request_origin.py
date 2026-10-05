"""要求ごとの監査用発行元。識別子は認可や承認の根拠には使用しない。"""

from __future__ import annotations

import inspect
import threading
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, replace
from functools import wraps
from typing import Annotated, Any, get_type_hints

from mcp.server import MCPServer
from pydantic import Field

from .redaction import redact_text


@dataclass(frozen=True)
class RequestOrigin:
    session_id: str
    server_instance_id: str
    origin_scope: str
    client_name: str | None = None
    client_version: str | None = None
    request_id: str | None = None
    task_id: str | None = None


_INSTANCE_ID = str(uuid.uuid4())
_PROCESS_ORIGIN = RequestOrigin(_INSTANCE_ID, _INSTANCE_ID, "process")
_CURRENT: ContextVar[RequestOrigin | None] = ContextVar("wlmcp_request_origin", default=None)
_CONNECTION_LOCK = threading.Lock()
_STATE_KEY = "windows_local_mcp.audit_session_id"

# 会話本文や秘密情報をラベルに入れず、短い追跡用の名前だけを許可する。
TaskId = Annotated[
    str | None,
    Field(
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$",
        description="Optional task label, e.g. docs-fix. Repeat on every call for this task; "
        "omit when unused. Tracking only, not an authorization boundary. Never include secrets.",
    ),
]


def current_origin() -> RequestOrigin:
    return _CURRENT.get() or _PROCESS_ORIGIN


def origin_fields(origin: RequestOrigin | None = None) -> dict[str, str | None]:
    return asdict(origin or current_origin())


@contextmanager
def use_origin(origin: RequestOrigin):
    """並行要求とワーカースレッドの間で発行元を混同しない。"""
    token = _CURRENT.set(origin)
    try:
        yield origin
    finally:
        _CURRENT.reset(token)


def _safe_metadata(value: object, limit: int = 120) -> str | None:
    if value is None:
        return None
    # 制御文字を除去してから伏せ字にする。巨大な自己申告文字列も保存しない。
    clean = "".join(
        char for char in str(value)[:2048]
        if char.isprintable() and not 0xD800 <= ord(char) <= 0xDFFF
    )
    return redact_text(clean)[:limit] or None


def origin_from_context(ctx: Any) -> RequestOrigin:
    """SDK 2.x の要求別 Session proxy から接続を取得する境界。"""
    # Session 自体は要求ごとに作り直されるため、proxy の ID は使用しない。
    connection = getattr(ctx, "connection", None)
    if connection is None:
        connection = getattr(getattr(ctx, "session", None), "_connection", None)
    state = getattr(connection, "state", None)
    if isinstance(state, dict):
        with _CONNECTION_LOCK:
            session_id = state.setdefault(_STATE_KEY, str(uuid.uuid4()))
        scope = "connection"
        if getattr(ctx, "request", None) is not None and not getattr(connection, "session_id", None):
            scope = "request"
    else:
        # SDK から接続情報を得られない場合、別要求を同一接続と推測しない。
        session_id, scope = str(uuid.uuid4()), "request"
    params = getattr(connection, "client_params", None)
    client = getattr(params, "client_info", None)
    return RequestOrigin(
        session_id=session_id,
        server_instance_id=_INSTANCE_ID,
        origin_scope=scope,
        client_name=_safe_metadata(getattr(client, "name", None)),
        client_version=_safe_metadata(getattr(client, "version", None)),
        request_id=_safe_metadata(getattr(ctx, "request_id", None)),
    )


async def origin_middleware(ctx: Any, call_next: Any) -> Any:
    with use_origin(origin_from_context(ctx)):
        return await call_next(ctx)


def _with_task_argument(function: Any) -> Any:
    """全 MCP ツールに同じ省略可能引数を公開し、実装の引数とは分離する。"""
    original = inspect.unwrap(function)
    hints = get_type_hints(original, include_extras=True)
    signature = inspect.signature(function)
    if "task_id" in signature.parameters:
        raise TypeError("task_id is reserved for per-request audit attribution")
    parameters = [
        param.replace(annotation=hints.get(param.name, param.annotation))
        for param in signature.parameters.values()
    ]
    parameters.append(inspect.Parameter(
        "task_id", inspect.Parameter.KEYWORD_ONLY, default=None, annotation=TaskId
    ))

    @wraps(function)
    def synchronous(*args: Any, task_id: str | None = None, **kwargs: Any) -> Any:
        with use_origin(replace(current_origin(), task_id=_safe_metadata(task_id, 80))):
            return function(*args, **kwargs)

    @wraps(function)
    async def asynchronous(*args: Any, task_id: str | None = None, **kwargs: Any) -> Any:
        with use_origin(replace(current_origin(), task_id=_safe_metadata(task_id, 80))):
            return await function(*args, **kwargs)

    wrapped = asynchronous if inspect.iscoroutinefunction(function) else synchronous
    wrapped.__signature__ = signature.replace(  # type: ignore[attr-defined]
        parameters=parameters, return_annotation=hints.get("return", signature.return_annotation)
    )
    return wrapped


class OriginMCPServer(MCPServer):
    """接続の監査情報とツールの task_id を統一して設定する。"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        middleware = [origin_middleware, *kwargs.pop("middleware", [])]
        super().__init__(*args, middleware=middleware, **kwargs)

    def add_tool(self, fn: Any, *args: Any, **kwargs: Any) -> None:
        super().add_tool(_with_task_argument(fn), *args, **kwargs)
