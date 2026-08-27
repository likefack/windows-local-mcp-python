from __future__ import annotations

import os
import sys
from io import TextIOWrapper
from typing import Any

import anyio
from mcp.server.stdio import stdio_server


class MCPStdioUnavailable(RuntimeError):
    """The MCP stdio transport cannot establish a bounded WLMCP-owned wire."""


def _duplicate_utf8_stream(fd: int, mode: str, *, errors: str) -> TextIOWrapper:
    """Duplicate one protocol fd without mutating the process-wide standard handles."""

    duplicate = os.dup(fd)
    try:
        binary = os.fdopen(duplicate, mode, closefd=True)
        return TextIOWrapper(
            binary,
            encoding="utf-8",
            errors=errors,
            newline="",
            write_through="w" in mode,
        )
    except Exception:
        try:
            os.close(duplicate)
        except OSError:
            pass
        raise


async def run_windows_stdio_server(server: Any) -> None:
    """Serve MCP over duplicated stdio pipes without SDK fd 0/1 rebinding.

    MCP Python SDK 2.x normally claims fd 0/1 and repoints the process-wide Win32
    standard-handle slots while serving. WLMCP does not need that global mutation:
    command workers already receive DEVNULL for stdin/stdout/stderr, while helper
    probes capture their output explicitly. Keeping the protocol on private,
    non-inheritable duplicate descriptors avoids changing the process-wide standard
    handles and removes a Windows failure mode where the first MCP frame closes the
    wire after the SDK descriptor claim.
    """

    if os.name != "nt":
        await server.run_stdio_async()
        return

    lowlevel = getattr(server, "_lowlevel_server", None)
    lowlevel_run = getattr(lowlevel, "run", None)
    create_options = getattr(lowlevel, "create_initialization_options", None)
    if lowlevel is None or not callable(lowlevel_run) or not callable(create_options):
        raise MCPStdioUnavailable(
            "installed MCP SDK does not expose the stdio server surface bound by WLMCP"
        )

    try:
        stdin_fd = sys.stdin.buffer.fileno()
        stdout_fd = sys.stdout.buffer.fileno()
    except (AttributeError, OSError, ValueError) as error:
        raise MCPStdioUnavailable("stdio protocol descriptors are unavailable") from error

    stdin_text: TextIOWrapper | None = None
    stdout_text: TextIOWrapper | None = None
    stdin_async: anyio.AsyncFile[str] | None = None
    stdout_async: anyio.AsyncFile[str] | None = None
    try:
        stdin_text = _duplicate_utf8_stream(stdin_fd, "rb", errors="replace")
        stdout_text = _duplicate_utf8_stream(stdout_fd, "wb", errors="strict")
        stdin_async = anyio.wrap_file(stdin_text)
        stdout_async = anyio.wrap_file(stdout_text)

        async with stdio_server(stdin=stdin_async, stdout=stdout_async) as (
            read_stream,
            write_stream,
        ):
            await lowlevel_run(read_stream, write_stream, create_options())
    except MCPStdioUnavailable:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise MCPStdioUnavailable("WLMCP stdio transport failed closed") from error
    finally:
        if stdin_async is not None:
            try:
                await stdin_async.aclose()
            except (OSError, ValueError):
                pass
        elif stdin_text is not None:
            try:
                stdin_text.close()
            except (OSError, ValueError):
                pass

        if stdout_async is not None:
            try:
                await stdout_async.aclose()
            except (OSError, ValueError):
                pass
        elif stdout_text is not None:
            try:
                stdout_text.close()
            except (OSError, ValueError):
                pass


def run_stdio_server(server: Any) -> None:
    """Synchronous production entrypoint for the WLMCP stdio transport."""

    anyio.run(run_windows_stdio_server, server)
