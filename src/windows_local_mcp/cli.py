from __future__ import annotations

import argparse
import json
import sys

from .approval_ui import run_approval_ui
from .audit import AuditStore
from .config import load_settings
from .timeline import timeline_entry, timeline_list
from .util import canonical_json, utc_now_iso


def main() -> None:
    parser = argparse.ArgumentParser(prog="windows-local-mcp")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("server", help="MCP server を stdio で起動")
    subparsers.add_parser("approvals", help="ローカル承認 UI を起動")

    audit_parser = subparsers.add_parser("audit", help="最近の監査ログを表示")
    audit_parser.add_argument("--limit", type=int, default=20)
    audit_parser.add_argument("--status", default=None)

    timeline_parser = subparsers.add_parser(
        "timeline", help="Activity と rollback 情報を上限付きで表示"
    )
    timeline_parser.add_argument("--limit", type=int, default=20)
    timeline_parser.add_argument("--operation", default=None)

    subparsers.add_parser(
        "resolve-codex-sandbox",
        help="この Windows PC で実行可能な Codex Sandbox backend を解決",
    )
    subparsers.add_parser(
        "verify-codex-sandbox",
        help="この Windows PC 上で Codex Sandbox の境界を実機検証",
    )
    subparsers.add_parser(
        "verify-git-broker",
        help="pinned Git を Automatic Git Broker 境界内で実機検証し live marker を更新",
    )

    args = parser.parse_args()

    if args.command == "resolve-codex-sandbox":
        from .sandbox_backend import resolve_codex_sandbox_backend

        backend = resolve_codex_sandbox_backend(load_settings())
        print(json.dumps(backend.as_dict(), ensure_ascii=False, indent=2))
        return

    if args.command == "verify-codex-sandbox":
        from .sandbox_backend import (
            codex_sandbox_live_verification_status,
            resolve_codex_sandbox_backend,
        )
        from .sandbox_live_verification_lifecycle import (
            ensure_codex_sandbox_live_verification,
        )

        settings = load_settings()
        lifecycle = ensure_codex_sandbox_live_verification(settings, force=True)
        inspection = codex_sandbox_live_verification_status(
            settings, resolve_codex_sandbox_backend(settings)
        )
        evidence = inspection.get("evidence")
        result = dict(evidence) if isinstance(evidence, dict) else {}
        route_eligible = inspection.get("status") == "verified"
        result["route_eligible"] = route_eligible
        result["lifecycle"] = lifecycle
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if not route_eligible:
            raise SystemExit(1)
        return

    if args.command == "verify-git-broker":
        from .git_broker_live_verify import verify_git_broker_live

        result = verify_git_broker_live(load_settings())
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if result.get("route_eligible") is not True:
            raise SystemExit(1)
        return

    if args.command == "server":
        # Context bridge sidecars are captured before server Runtime initialization sanitizes
        # LOCAL_MCP_* environment values, then bound to the validated production runtime.
        from .context_export import load_context_export_config
        from .context_export_protocol import register_context_export_tools
        from .context_read import load_context_read_config, register_context_read_tools

        context_export_config = load_context_export_config()
        context_read_config = load_context_read_config()

        from .mcp_stdio import run_stdio_server
        from .server import mcp, runtime

        register_context_export_tools(mcp, context_export_config, runtime)
        register_context_read_tools(mcp, context_read_config, runtime)
        runtime.start_sandbox_live_verification()
        # stdout は MCP frame 専用なので、人向けの起動案内は stderr にだけ出します。
        print(
            "Windows Local MCP の起動に成功しました。ChatGPT からの接続を待っています。",
            file=sys.stderr,
            flush=True,
        )
        print(
            "このウィンドウを閉じないでください。終了するには Ctrl+C を押します。",
            file=sys.stderr,
            flush=True,
        )
        run_stdio_server(mcp)
        return

    if args.command == "approvals":
        run_approval_ui()
        return

    if args.command == "audit":
        store = AuditStore(load_settings())
        print(
            json.dumps(
                store.list_operations(limit=args.limit, status=args.status),
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    if args.command == "timeline":
        settings = load_settings()
        store = AuditStore(settings)
        result = (
            timeline_entry(settings, store, args.operation)
            if args.operation
            else timeline_list(settings, store, args.limit)
        )
        access_id = store.create_operation(
            tool_name="timeline_cli",
            tier="read",
            status="succeeded",
            cwd=str(settings.workspace_root),
            request={"limit": args.limit, "operation_id": args.operation},
        )
        store.update_operation(
            access_id,
            finished_at=utc_now_iso(),
            result_json=canonical_json(
                {"returned": 1 if args.operation else len(result)}
            ),
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
