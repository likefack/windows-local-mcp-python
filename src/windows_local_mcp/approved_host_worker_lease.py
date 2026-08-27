from __future__ import annotations

from dataclasses import dataclass

from .approved_host_authority import (
    APPROVED_HOST_AUTHORITY_STATE_VERSION,
    AuthorityWorkerLease,
    _write_json_exclusive,
)
from .util import utc_now_iso


@dataclass
class HardenedAuthorityWorkerLease(AuthorityWorkerLease):
    """Production completion lease; only a normally returned worker may create a proof."""

    def finalize_normal_return(self, exit_code: int) -> None:
        if self.child_started and not self.postflight_verified:
            return
        payload = {
            "version": APPROVED_HOST_AUTHORITY_STATE_VERSION,
            "operation_id": self.operation_id,
            "service_epoch": self.service_epoch,
            "authority_nonce": self.authority_nonce,
            "child_started": self.child_started,
            "postflight_verified": self.postflight_verified,
            "worker_returned_normally": True,
            "worker_exit_code": int(exit_code),
            "completed_at": utc_now_iso(),
        }
        _write_json_exclusive(self.proof_path, payload)
