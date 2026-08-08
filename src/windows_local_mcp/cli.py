from __future__ import annotations

import argparse
import json
import os

from .approval_ui import run_approval_ui
from .audit import AuditStore
from .config import load_settings
from .timeline import timeline_entry, timeline_list
from .util import canonical_json, utc_now_iso


def main() -> None:
    parser = argparse.ArgumentParser(prog="windows-local-mcp")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("server", help="MCP serverをstdioで起動")
    subparsers.add_parser("approvals", help="ローカル承認UIを起動")

    audit_parser = subparsers.add_parser("audit", help="最近の監査ログを表示")
    audit_parser.add_argument("--limit", type=int, default=20)
    audit_parser.add_argument("--status", default=None)

    timeline_parser = subparsers.add_parser(
        "timeline", help="Show bounded human-readable activity and rollback metadata"
    )
    timeline_parser.add_argument("--limit", type=int, default=20)
    timeline_parser.add_argument("--operation", default=None)

    isolation_parser = subparsers.add_parser(
        "setup-network-isolation",
        help="Create the local AppContainer profiles and ACL grants used by Safe Tier",
    )
    isolation_parser.add_argument("--config", required=True)

    args = parser.parse_args()

    if args.command == "setup-network-isolation":
        os.environ["LOCAL_MCP_CONFIG"] = args.config
        os.environ.pop("LOCAL_MCP_ROOT", None)
        from .appcontainer import create_appcontainer_profiles

        result = create_appcontainer_profiles(load_settings())
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    if args.command == "server":
        from .server import main as server_main

        server_main()
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
