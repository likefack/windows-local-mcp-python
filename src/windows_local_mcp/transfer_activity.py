"""Live Activity 用に、転送の状態だけを変更せず読み取る。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from .config import Settings
from .paths import read_verified_path_bytes
from .resources import NamedControlPlaneLock

_MANIFEST_MAX_BYTES = 64 * 1024
_ACTIVE_STATES = {"preparing", "open"}
_TERMINAL_STATES = {"completed", "committed", "cancelled", "expired", "failed"}


@dataclass(frozen=True)
class TransferActivityState:
    state: str
    finished_at: str | None = None


def _canonical_uuid(value: str) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except ValueError:
        return False


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise TypeError("invalid transfer timestamp")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("transfer timestamp requires a timezone")
    return parsed


def read_transfer_activity_state(
    settings: Settings,
    transfer_id: str,
    operation_id: str,
    direction: str,
    now: datetime,
) -> TransferActivityState:
    """検証済みの状態と終了日時だけを返し、取得できない場合は unavailable とする。"""
    unavailable = TransferActivityState("unavailable")
    # 入力をパスやロック名へ組み込む前に、正規形式の UUID へ限定する。
    if (
        not _canonical_uuid(transfer_id)
        or not _canonical_uuid(operation_id)
        or not isinstance(direction, str)
        or direction not in {"download", "upload"}
    ):
        return unavailable
    try:
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            return unavailable
        path = settings.data_dir / "binary-transfers" / transfer_id / "manifest.json"
        # Windows の読取ハンドルが writer の原子的置換を妨げないよう同じロックを使う。
        with NamedControlPlaneLock(settings, f"transfer-{transfer_id}", timeout=0.05):
            manifest = json.loads(read_verified_path_bytes(path, _MANIFEST_MAX_BYTES).decode("utf-8"))
        if not isinstance(manifest, dict):
            return unavailable
        version = manifest.get("version")
        state = manifest.get("state")
        if (
            type(version) is not int
            or version not in {1, 2, 3, 4, 5}
            or manifest.get("operation_id") != operation_id
            or manifest.get("direction") != direction
            or state not in _ACTIVE_STATES | _TERMINAL_STATES
        ):
            return unavailable
        created = _timestamp(manifest.get("created_at"))
        expiry = (
            _timestamp(manifest["expires_at"])
            if "expires_at" in manifest
            else created + timedelta(seconds=settings.binary_transfer_ttl_seconds)
        )
        if expiry < created:
            return unavailable
        if state in _ACTIVE_STATES:
            # 表示上の期限切れだけを計算し、manifest・本文・監査には書き込まない。
            if now > expiry:
                return TransferActivityState("expired", expiry.isoformat())
            return TransferActivityState(state)
        try:
            finished = _timestamp(manifest.get(f"{state}_at")).isoformat()
        except (TypeError, ValueError):
            finished = None
        return TransferActivityState(state, finished)
    except Exception:  # noqa: BLE001 - 表示の取得失敗は通常操作へ伝播させない。
        # 表示用の失敗詳細に内部パスや本文を含めず、転送処理自体にも伝播させない。
        return unavailable
