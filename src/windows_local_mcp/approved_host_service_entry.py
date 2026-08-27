from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from .approved_host_authority import default_authority_state_root
from .approved_host_service import ApprovedHostAuthorityServer, _WindowsServiceHost


class HardenedApprovedHostAuthorityServer(ApprovedHostAuthorityServer):
    """Production authority surface: no same-user RPC can stop an active monitor."""

    def handle_request(self, client_pid: int, request: dict[str, Any]) -> dict[str, Any]:
        if str(request.get("action") or "") == "cancel":
            raise PermissionError(
                "Approved Host monitor cancellation is not exposed to the runtime user"
            )
        return super().handle_request(client_pid, request)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-sid", required=True)
    parser.add_argument(
        "--state-root",
        type=Path,
        default=default_authority_state_root(),
    )
    parser.add_argument("--console", action="store_true")
    args = parser.parse_args()

    def factory() -> HardenedApprovedHostAuthorityServer:
        return HardenedApprovedHostAuthorityServer(
            runtime_sid=args.runtime_sid,
            state_root=args.state_root,
        )

    if args.console:
        server = factory()
        try:
            server.serve()
        finally:
            server.close()
        return
    _WindowsServiceHost(factory).run()


if __name__ == "__main__":
    main()
