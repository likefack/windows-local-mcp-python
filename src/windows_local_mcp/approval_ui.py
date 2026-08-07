from __future__ import annotations

import json
import time

from .approval import verify_approval_bundle
from .audit import AuditStore
from .config import Settings, load_settings
from .executor import Executor
from .policy import NormalizedCommand, approval_hash
from .util import utc_now_iso


def _show(item: dict[str, object]) -> None:
    print("\n" + "=" * 80)
    print(f"Approval ID : {item['id']}")
    print(f"Created     : {item['created_at']}")
    print(f"Expires     : {item['request_expires_at']}")
    print(f"Tool        : {item['tool_name']}")
    print(f"CWD         : {item['cwd']}")
    print(f"Hash        : {item['request_hash']}")
    print("-" * 80)
    print(json.dumps(item["request"], ensure_ascii=False, indent=2))
    print("=" * 80)


def run_approval_ui(settings: Settings | None = None) -> None:
    settings = settings or load_settings()
    audit = AuditStore(settings)
    executor = Executor(settings, audit)
    print(f"Audit DB: {audit.db_path}")
    print("Pending approvals: y=approve and run once, n=reject, s=skip, q=quit")

    while True:
        pending = audit.list_pending_approvals()
        if not pending:
            try:
                time.sleep(1.0)
            except KeyboardInterrupt:
                return
            continue

        for item in pending:
            _show(item)
            decision = input("Decision [y/N/s/q]: ").strip().casefold()
            if decision == "q":
                return
            if decision == "s":
                continue
            note = input("Note (optional): ").strip()
            operation_id = str(item["id"])
            if decision not in {"y", "yes"}:
                audit.decide_approval(
                    operation_id,
                    approved=False,
                    approver=settings.default_approver,
                    note=note,
                )
                print("Rejected.")
                continue

            try:
                request = item["request"]
                if not isinstance(request, dict):
                    raise TypeError("invalid approval request")
                normalized = NormalizedCommand.model_validate(request["normalized_command"])
                manifest_digest = str(request["approval_manifest_digest"])
                expected_hash = approval_hash(
                    normalized=normalized,
                    reason=str(request.get("reason", "")),
                    risk_summary=str(request.get("risk_summary", "")),
                    manifest_digest=manifest_digest,
                )
                if expected_hash != item.get("request_hash"):
                    raise RuntimeError("approval request hash mismatch")
                verify_approval_bundle(
                    settings=settings,
                    operation_id=operation_id,
                    expected_digest=manifest_digest,
                )
                audit.approve_and_claim(
                    operation_id,
                    approver=settings.default_approver,
                    note=note,
                )
                executor.launch(operation_id, 0)
                print("Approved and launched once. The MCP client can poll the result.")
            except Exception as error:  # noqa: BLE001 - fail closed and persist any launch error
                audit.update_operation(
                    operation_id,
                    status="failed",
                    approval_status="rejected",
                    finished_at=utc_now_iso(),
                    error=f"approval validation or launch failed: {type(error).__name__}: {error}",
                )
                audit.add_event(
                    operation_id,
                    "approval_launch_failed",
                    {"error": f"{type(error).__name__}: {error}"[:1000]},
                )
                print(f"Not executed: {error}")
