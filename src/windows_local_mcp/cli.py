from __future__ import annotations

import argparse
import json

from .approval_ui import run_approval_ui
from .audit import AuditStore
from .config import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(prog="windows-local-mcp")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("server", help="MCPサーバーをstdioで起動")
    subparsers.add_parser("approvals", help="承認UIを起動")

    audit_parser = subparsers.add_parser("audit", help="最近の監査ログを表示")
    audit_parser.add_argument("--limit", type=int, default=20)
    audit_parser.add_argument("--status", default=None)

    args = parser.parse_args()

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


if __name__ == "__main__":
    main()
