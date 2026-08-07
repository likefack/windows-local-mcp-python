from __future__ import annotations

import json
import time
from datetime import UTC, datetime

from .audit import AuditStore
from .config import Settings, load_settings


def _is_expired(created_at: str, ttl_seconds: int) -> bool:
    created = datetime.fromisoformat(created_at)
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    return (datetime.now(UTC) - created).total_seconds() > ttl_seconds


def _show(item: dict[str, object]) -> None:
    print("\n" + "=" * 80)
    print(f"Approval ID : {item['id']}")
    print(f"Created     : {item['created_at']}")
    print(f"Tool        : {item['tool_name']}")
    print(f"CWD         : {item['cwd']}")
    print(f"Hash        : {item['request_hash']}")
    print("-" * 80)
    print(json.dumps(item["request"], ensure_ascii=False, indent=2))
    print("=" * 80)


def run_approval_ui(settings: Settings | None = None) -> None:
    settings = settings or load_settings()
    audit = AuditStore(settings)
    print(f"監査DB: {audit.db_path}")
    print("承認待ちを監視します。y=承認 n=拒否 s=保留 q=終了")

    while True:
        pending = audit.list_pending_approvals()
        if not pending:
            try:
                time.sleep(1.0)
            except KeyboardInterrupt:
                return
            continue

        for item in pending:
            if _is_expired(str(item["created_at"]), settings.approval_ttl_seconds):
                audit.update_operation(
                    str(item["id"]),
                    approval_status="expired",
                    status="expired",
                    error="承認期限を超えました",
                )
                audit.add_event(str(item["id"]), "expired", {})
                continue

            _show(item)
            decision = input("Decision [y/N/s/q]: ").strip().casefold()
            if decision == "q":
                return
            if decision == "s":
                continue

            note = input("メモ（空欄可）: ").strip()
            if decision in {"y", "yes"}:
                audit.decide_approval(
                    str(item["id"]),
                    approved=True,
                    approver=settings.default_approver,
                    note=note,
                )
                print("承認しました。")
            else:
                audit.decide_approval(
                    str(item["id"]),
                    approved=False,
                    approver=settings.default_approver,
                    note=note,
                )
                print("拒否しました。")
