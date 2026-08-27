from __future__ import annotations

import argparse
import ctypes
import os
import secrets
import subprocess
import threading
from pathlib import Path
from typing import Any, Mapping

from . import approved_host_service as _service
from .approved_host_authority import default_authority_state_root
from .approved_host_security import (
    HardenedAuthorityStateStore,
    assert_authority_service_security,
    assert_authority_state_security,
)
from .approved_host_service import ApprovedHostAuthorityServer, _WindowsServiceHost


class HardenedApprovedHostAuthorityServer(ApprovedHostAuthorityServer):
    """Production LocalSystem authority with immutable durable state and no monitor-stop RPC."""

    def __init__(self, *, runtime_sid: str, state_root: Path) -> None:
        if os.name != "nt":
            raise RuntimeError("Approved Host authority requires native Windows")
        if _service._current_process_sid() != _service._SYSTEM_SID:  # noqa: SLF001
            raise PermissionError("Approved Host authority must run as LocalSystem")
        self.runtime_sid = runtime_sid
        self.service_epoch = secrets.token_hex(32)
        self.store = HardenedAuthorityStateStore(state_root, self.service_epoch)
        # Provisioning, owner and DACL are security preconditions. The service never creates
        # an unprotected ProgramData namespace as a fallback.
        assert_authority_state_security(state_root)
        assert_authority_service_security(runtime_sid)
        if self.store.read_active() is not None:
            self.store.mark_recovery_required(
                "authority service restarted while an operation was active"
            )
        self._stop = threading.Event()
        self._workers_lock = threading.RLock()
        self._workers: dict[str, subprocess.Popen[Any]] = {}
        self._security_descriptor = ctypes.c_void_p()
        self._security_attributes = self._build_pipe_security(runtime_sid)

    def handle_request(
        self,
        client_pid: int,
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        # Re-check the persistent boundary on every RPC. A weakened service/state ACL must
        # never be treated as a transient configuration issue while Host is available.
        assert_authority_state_security(self.store.root)
        assert_authority_service_security(self.runtime_sid)
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
    args = parser.parse_args()

    def factory() -> HardenedApprovedHostAuthorityServer:
        return HardenedApprovedHostAuthorityServer(
            runtime_sid=args.runtime_sid,
            state_root=args.state_root,
        )

    _WindowsServiceHost(factory).run()


if __name__ == "__main__":
    main()
