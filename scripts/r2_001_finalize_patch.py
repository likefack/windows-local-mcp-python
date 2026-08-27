from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _write(path: str, text: str) -> None:
    (ROOT / path).write_text(text, encoding="utf-8", newline="\n")


def replace_exact(path: str, old: str, new: str, *, count: int = 1) -> None:
    text = _read(path)
    actual = text.count(old)
    if actual != count:
        raise RuntimeError(f"{path}: expected {count} exact matches, found {actual}: {old[:120]!r}")
    _write(path, text.replace(old, new, count))


def replace_regex(path: str, pattern: str, replacement: str, *, count: int = 1) -> None:
    text = _read(path)
    updated, actual = re.subn(pattern, replacement, text, count=count, flags=re.DOTALL)
    if actual != count:
        raise RuntimeError(f"{path}: expected {count} regex matches, found {actual}: {pattern[:120]!r}")
    _write(path, updated)


def patch_python() -> None:
    replace_exact(
        "src/windows_local_mcp/approved_host_authority.py",
        "from typing import Any, Mapping\n",
        "from collections.abc import Mapping\nfrom typing import Any\n",
    )
    replace_exact(
        "src/windows_local_mcp/approved_host_authority.py",
        '        raise RuntimeError(f"Approved Host authority state is not an object: {path}")\n',
        '        raise TypeError(f"Approved Host authority state is not an object: {path}")\n',
    )
    replace_exact(
        "src/windows_local_mcp/approved_host_abnormal_verification.py",
        "    except Exception:\n        generation_blocked = True\n",
        "    except (OSError, PermissionError, RuntimeError, TypeError, ValueError):\n        generation_blocked = True\n",
    )
    replace_exact(
        "src/windows_local_mcp/approved_host_service.py",
        "        except Exception:\n            try:\n                self._set_status(_SERVICE_STOPPED, win32_exit=1)\n            except Exception:\n                pass\n",
        "        except Exception:  # noqa: BLE001 - SCM callback must not escape on fatal service error\n            try:\n                self._set_status(_SERVICE_STOPPED, win32_exit=1)\n            except Exception:  # noqa: BLE001,S110 - SCM status channel may already be unavailable\n                pass\n",
    )
    replace_exact(
        "src/windows_local_mcp/executor.py",
        "        except Exception:\n            return False\n        return str(probe.get(\"active_operation_id\") or \"\") == str(operation[\"id\"])\n",
        "        except (OSError, PermissionError, RuntimeError, TypeError, ValueError):\n            return False\n        return str(probe.get(\"active_operation_id\") or \"\") == str(operation[\"id\"])\n",
    )

    server_path = "src/windows_local_mcp/server.py"
    replace_exact(
        server_path,
        "from .approval import (\n",
        "from .approved_host_policy import assert_approved_host_authority_available\nfrom .approval import (\n",
    )
    new_capability = '''def _approved_host_capability() -> dict[str, Any]:
    properties = {
        name: {"status": "unverified", "unit_tested": True}
        for name in (
            "runtime_immutability",
            "authority_service_boundary",
            "durable_recovery_state",
            "requester_token_child",
            "monitor_access_denial",
            "control_plane_tamper_detection",
            "approval_integrity",
            "job_descendant_handling",
            "outside_job_same_user_process_detection",
            "timeout_termination",
        )
    }
    status: dict[str, Any] = {
        "configured": runtime.settings.approved_host_enabled,
        "enabled": runtime.settings.approved_host_enabled,
        "available": False,
        "execution_route_available": False,
        "unit_tested": True,
        "live_verified": False,
        "windows_live_verified": False,
        "verification_scope": "runtime_and_authority_preflight_only",
        "properties": properties,
        "execution_time_recheck": True,
        "runtime_preflight": {"status": "not_run"},
        "authority_preflight": {"status": "not_run"},
    }
    if not runtime.settings.approved_host_enabled:
        status["unavailable_reason"] = "disabled by configuration"
        return status
    try:
        evidence = assert_approved_host_runtime_immutable()
    except Exception as error:  # noqa: BLE001 - capability display must remain available
        message = redact_text(f"{type(error).__name__}: {error}")
        status["unavailable_reason"] = message
        status["runtime_preflight"] = {"status": "failed", "error": message}
        properties["runtime_immutability"].update(
            status="failed" if os.name == "nt" else "unverified",
            verification_kind=(
                "windows_live_preflight" if os.name == "nt" else "non_windows_preflight"
            ),
        )
        return status

    properties["runtime_immutability"].update(
        status="verified" if os.name == "nt" else "unverified",
        verification_kind=(
            "windows_live_preflight" if os.name == "nt" else "non_windows_preflight"
        ),
    )
    status["runtime_preflight"] = {
        "status": "passed",
        "version": evidence.get("version"),
        "scope": evidence.get("scope"),
        "path_count": evidence.get("path_count"),
        "file_count": evidence.get("file_count"),
        "directory_count": evidence.get("directory_count"),
        "ancestor_directory_count": evidence.get("ancestor_directory_count"),
        "digest": evidence.get("digest"),
    }
    try:
        authority = assert_approved_host_authority_available()
    except Exception as error:  # noqa: BLE001 - capability display must remain available
        message = redact_text(f"{type(error).__name__}: {error}")
        status["unavailable_reason"] = message
        status["authority_preflight"] = {"status": "failed", "error": message}
        return status

    status["available"] = True
    status["execution_route_available"] = True
    status["authority_preflight"] = {
        "status": "passed",
        "healthy": bool(authority.get("healthy")),
        "service_epoch": authority.get("service_epoch"),
        "active_operation_id": authority.get("active_operation_id"),
    }
    properties["authority_service_boundary"].update(
        status="verified" if os.name == "nt" else "unverified",
        verification_kind=(
            "authenticated_service_preflight" if os.name == "nt" else "unsupported"
        ),
    )
    # Full monitor-access denial, requester-token preservation, abnormal recovery, and WMI
    # worker-loss behavior require the explicit Windows live verifiers. Availability never
    # upgrades those release-verification properties to live-verified evidence.
    return status
'''
    replace_regex(
        server_path,
        r"def _approved_host_capability\(\) -> dict\[str, Any\]:\n.*?(?=\ndef _broker_helper_capability)",
        new_capability + "\n",
    )


def patch_security_contract() -> None:
    path = "SECURITY_CONTRACT.md"
    replace_regex(
        path,
        r"同日、Approved Host の guarded interval について、same Windows user authority の child が worker／監視 process を\n.*?kill／bypass／restart 回帰を Windows 実機で通すことを先に要求します。",
        """同日、Approved Host の guarded interval について、same Windows user authority の child が worker／監視 process を
停止して postflight を回避でき、restart 時の stale reconciliation だけでは永続 tamper latch が残らないことを
WLMCP-R2-001 として valid と判定しました。same-desktop UAC elevation は Windows security boundary として受理せず、
この問題を受容済み残存 risk に移しません。同日 main に入った Approved Host 全面 fail-closed は temporary exploit
containment／product regression の履歴であり、trusted operator は final remediation として拒否しました。

current remediation candidate は monitor／postflight worker を LocalSystem service へ分離し、実 command だけを verified
requester の非昇格 Windows user token で起動します。service-owned ProgramData durable state、service epoch、normal-return
completion proof、requester-user WMI／CIM process census を必須境界とします。runtime user／Approved Host child に service
stop/change-config、monitor cancellation、SYSTEM worker の terminate／suspend／duplicate-handle／VM-write／token-manipulation
authority を与えません。GitHub Hosted CI はこの OS boundary の live evidence ではないため、normal／abnormal Windows live
verification が成功するまで WLMCP-R2-001 は `valid / remediation implemented / live verification pending` とします。""",
    )
    replace_regex(
        path,
        r"### 2\.4 Approved Host\n.*?(?=\n旧 Safe Tier)",
        """### 2.4 Approved Host

Approved Host は Codex Sandbox／Broker では満たせない処理を、separate one-shot human approval 後に通常の Windows user
authority で実行する中核 route です。project-controlled code-loader と workspace executable は引き続き拒否します。
Sandbox failure から Host への automatic fallback はありません。

production execution は immutable Program Files runtime と authenticated LocalSystem authority service の両方を必要とします。
monitor／postflight は LocalSystem worker が所有し、実 child は pipe requester の verified non-elevated token を
`CreateProcessAsUserW` で使用します。same-desktop UAC elevation を security boundary としません。

service-owned durable `active.json` は normal verified completion まで immutable とし、worker kill、service restart、channel
loss、postflight mismatch、Job 外 helper 残存では解除しません。active Approved Host monitor は runtime-user `stop_job` から
停止できません。異常 state の解除は elevated Administrator による explicit reviewed recovery だけです。

この route の source／CI implementation と Windows live verification を混同しません。release status は normal-path と
WMI helper＋SYSTEM-worker-loss＋service-restart abnormal-path live verification が通るまで pending のままです。
""",
    )
    replace_regex(
        path,
        r"### E\. Approved Host boundary\n.*?(?=\n### F\.)",
        """### E. Approved Host boundary

- Codex Sandbox とは別の one-shot human approval を必要とする。
- project-controlled code-loader と workspace 内 executable は Approved Host で受理せず、Codex Sandbox の snapshot-only route を要求する。
- monitor／postflight owner は LocalSystem service 配下とし、実 command は元 requester の non-elevated Windows user token で起動する。
- runtime user／Approved Host child から monitor／worker／service の terminate、suspend、thread control、duplicate handle、VM write、token manipulation、security descriptor rewrite、SCM stop/change-config を許さない。
- same-desktop UAC elevation だけを authority separation の根拠にしない。
- durable pending／recovery／epoch state は LocalSystem-owned protected ProgramData namespace に置き、normal verified completion まで immutable active latch を残す。
- child／worker／monitor の異常終了、channel loss、timeout、postflight 未完了、control-plane mismatch、service restart、旧 epoch proof を restart 後にも残る fail-closed state へ結合する。
- Windows Job Object の全 descendant と、WMI／CIM 等の Job 外 requester-user process creation の双方を閉じる。process identity を列挙できない、または期限内に終了しない場合も postflight を成功扱いしない。
- Host の device、network、external service、process side effect を workspace rollback 可能とは表示しない。
- Hosted CI の unit/integration evidence を Windows service/process authority の live verification と表示しない。normal／abnormal live verification 未完了なら finding を closed としない。
""",
    )
    replace_exact(
        path,
        "- Approved Host は current v1 では execution unavailable です。将来再有効化した場合、人間が明示的に secret access を承認する operation についてまで絶対に読めないことは保証しません。",
        "- Approved Host は LocalSystem authority boundary が healthy な場合に separate approval 後の通常 Windows user command を実行できます。人間が明示的に secret access を承認する operation についてまで絶対に読めないことは保証しません。",
    )
    replace_regex(
        path,
        r"Approved Host も capability truthfulness の対象です。`approved_host_enabled=true`、`request_host_command` surface、\n.*?worker を spawn しません。",
        """Approved Host も capability truthfulness の対象です。`approved_host_enabled=true`、`request_host_command` surface、
または pending／approved row の存在を execution availability と同一視しません。`available=true` は immutable runtime と
authenticated authority service の current preflight が両方成功した場合だけです。source／unit evidence や service health を
`live_verified`／`windows_live_verified` へ昇格しません。R2-001 の release-level live verification 未完了は明示的に pending とします。""",
    )
    replace_exact(
        path,
        "Approved Host の same-principal monitor termination／postflight bypass はこの受容済み残存 risk に含めません。\ncurrent v1 は当該 capability を停止して解消し、将来再有効化する場合は Section E の boundary を先に要求します。",
        "Approved Host の same-principal monitor termination／postflight bypass はこの受容済み残存 risk に含めません。\nSection E の LocalSystem authority boundary と required Windows live verification を満たさない状態では finding を未解決のまま扱います。",
    )


def patch_spec() -> None:
    path = "SPEC.md"
    replace_exact(
        path,
        "`approved_host_enabled` remains a configuration-intent field for compatibility, but current v1 deliberately makes the Approved Host execution route unavailable after validating WLMCP-R2-001. The presence of this setting, `request_host_command`, or pending/approved rows does not imply that an Approved Host worker can start. The production runtime gate rejects the route before worker spawn. Re-enabling it requires an independently justified Windows security boundary for the monitor/postflight owner and durable tamper state; same-desktop UAC elevation alone is not accepted as that boundary.",
        "`approved_host_enabled` controls intent, but it does not by itself make the route available. Approved Host execution additionally requires an immutable runtime and a healthy authenticated LocalSystem authority service. The monitor/postflight worker runs as LocalSystem while the final command uses the verified non-elevated requester token. Pending/approved rows never bypass this authority gate, and same-desktop UAC elevation is not accepted as the boundary. WLMCP-R2-001 remains live-verification-pending until the required normal and abnormal Windows service/process tests pass.",
    )
    replace_exact(
        path,
        "Keeping the `git_info` and `execute_readonly` MCP surfaces does not constitute automatic Git availability, and the unavailable Approved Host route is not a fallback.",
        "Keeping the `git_info` and `execute_readonly` MCP surfaces does not constitute automatic Git availability. Approved Host is a separately approved route and is never an implicit Git or Sandbox fallback.",
    )
    replace_exact(
        path,
        "- Approved Host は current v1 では execution unavailable です。project-controlled code-loader と workspace 内 executable を Host request で拒否する既存 defense-in-depth は残りますが、Sandbox failure から Host への fallback はありません。",
        "- Approved Host は project-controlled code-loader と workspace 内 executable を Host request で拒否します。eligible non-project-controlled Host command は LocalSystem monitor／requester-user child boundaryを満たす場合だけ separate approval 後に実行でき、Sandbox failure からの fallback はありません。",
    )
    replace_exact(
        path,
        "- Approved Host 用の同種 lock／manifest code は将来 route の defense-in-depth として残り得ますが、current v1 では production gate が Host worker spawn 前に停止するため実行境界として成立したとは表示しません。",
        "- Approved Host は同じ workspace-wide lock／manifest binding を維持し、LocalSystem worker が postflight 完了までその control interval を所有します。",
    )
    replace_exact(
        path,
        "`request_host_command` remains a compatibility surface that only stages local approval state and immutable inputs. In current v1 it does not lead to host execution: even an upgrade-existing queued/approved operation is rejected by the production gate before worker spawn. There is no implicit Codex Sandbox to Approved Host fallback and no model-facing `execute_approved` tool.",
        "`request_host_command` stages local one-shot approval state and immutable inputs. After local approve-and-claim, eligible Host operations execute only through the authenticated LocalSystem authority; old queued/approved rows still pass the same current generation, immutable manifest, executable identity, TTL, and authority checks before any worker/child launch. There is no implicit Codex Sandbox to Approved Host fallback and no model-facing `execute_approved` tool.",
    )
    replace_exact(
        path,
        "Approved Host の non-project-code-loader path は current v1 では execution unavailable です。将来再有効化する場合も Codex Sandbox と同じ source-read isolation を暗黙に主張せず、別の authority-boundary contract を満たす必要があります。",
        "Approved Host の non-project-code-loader path は Codex Sandbox と同じ source-read isolation を暗黙に主張しません。LocalSystem monitor／durable state／requester-user child authority boundary と one-shot immutable approval contract を満たす場合だけ実行します。",
    )
    replace_regex(
        path,
        r"Current v1 does not launch Approved Host workers\. Historical/future Approved Host Job Object, same-user process census, postflight, and runtime-immutability code remains defense-in-depth and testable implementation material but is not an active security guarantee while WLMCP-R2-001 capability reduction is in force\. A stale or already-approved Host operation cannot revive this path because `Executor\.launch\(\)` performs the production gate before worker creation\.",
        "Approved Host workers are launched only by the authenticated LocalSystem authority service. The SYSTEM worker owns Job Object, requester-user process census, postflight, and durable completion; the final command remains under the verified non-elevated requester token. A stale or already-approved Host operation cannot bypass runtime immutability, current control-plane generation, approval binding, or authority health gates.",
    )
    replace_exact(
        path,
        "4. `approved_host`: compatibility/configuration surface only in current v1; execution is unavailable and fails closed before worker spawn.",
        "4. `approved_host`: separate one-shot approval route using a LocalSystem monitor/postflight authority and ordinary non-elevated requester-user command token; unavailable unless runtime and authority preflight both pass.",
    )
    replace_exact(
        path,
        "Missing CLI, incomplete UAC setup, incompatible backend, initialization/policy/launch failure, or timeout fails closed. A separate Approved Host request may still be staged for compatibility, but current v1 will reject execution before worker spawn.",
        "Missing CLI, incomplete UAC setup, incompatible backend, initialization/policy/launch failure, or timeout fails closed. A separate Approved Host request is never an automatic fallback and follows its own LocalSystem authority/approval contract.",
    )
    replace_exact(
        path,
        "ACL cannot distinguish two processes running as the same Windows user. MCP filesystem tools still cannot reach `data_dir` because it is outside workspace, and artifact paths are validated before special retrieval such as ADB screenshots. This same-user limitation is one reason current v1 does not treat Approved Host postflight monitoring as a complete security boundary and disables that execution route.",
        "ACL cannot distinguish two processes running as the same Windows user. MCP filesystem tools still cannot reach `data_dir` because it is outside workspace, and artifact paths are validated before special retrieval such as ADB screenshots. Approved Host therefore does not place its authoritative monitor/recovery latch in the same-user `data_dir`: LocalSystem owns the monitor and protected ProgramData authority state, while user-owned control-plane state remains an independently checked postflight input.",
    )
    replace_exact(
        path,
        "- `request_host_command`: non-read-only, non-destructive, closed-world because it only creates an approval request; current v1 rejects any resulting Approved Host execution before worker spawn;",
        "- `request_host_command`: non-read-only, non-destructive, closed-world because it only creates an approval request; any later execution requires local approve-and-claim plus immutable binding and LocalSystem authority checks;",
    )


def patch_readme() -> None:
    path = "README.md"
    replace_regex(
        path,
        r"4\. \*\*Approved Host\*\*\n(?:   - .*\n)+(?=\n旧 Safe Tier)",
        """4. **Approved Host**
   - Codex Sandbox／Broker では満たせない eligible command を、separate one-shot local approval 後に通常の Windows user authority で実行する route です。
   - monitor／postflight worker は LocalSystem service が所有し、実 command は verified non-elevated requester token で起動します。same-desktop UAC elevation を security boundary としません。
   - `%ProgramData%\\WindowsLocalMCP\\ApprovedHostAuthority` の LocalSystem-owned durable latch は normal verified completion まで残り、worker kill／service restart／postflight failure では explicit administrator recovery を要求します。
   - project-controlled code-loader と workspace executable は引き続き Host で拒否し、Sandbox failure から Host へ automatic fallback しません。
   - WLMCP-R2-001 はこの root-remediation branch で implementation 済みですが、required Windows normal／abnormal live verification が終わるまで fixed／closed と扱いません。
""",
    )
    replace_exact(
        path,
        "Python 3.11 以上を使用します。repository checkout と `.venv` は通常 user が編集できる開発環境であり、Broker／Codex Sandbox の開発・テスト用です。Approved Host は current v1 では runtime が immutable かどうかにかかわらず execution unavailable です。開発中は `approved_host_enabled = false` を推奨します。",
        "Python 3.11 以上を使用します。repository checkout と `.venv` は通常 user が編集できる開発環境であり、Broker／Codex Sandbox の開発・テスト用です。Approved Host production execution は immutable Program Files runtime と LocalSystem authority service を必要とするため、editable checkout では `approved_host_enabled = false` を推奨します。",
    )
    replace_exact(
        path,
        "Git executable の path／SHA-256 も approved route の trust anchor として設定できますが、current v1 ではこれらを設定しても automatic Git Broker execution は有効になりません。workspace-controlled repository metadata を無承認 Git child から安全に閉じ込められることが未実証なためです。Approved Host も current v1 では unavailable なので、その代替経路にはなりません。",
        "Git executable の path／SHA-256 も approved route の trust anchor として設定できますが、current v1 ではこれらを設定しても automatic Git Broker execution は有効になりません。workspace-controlled repository metadata を無承認 Git child から安全に閉じ込められることが未実証なためです。Approved Host は別の one-shot approval／LocalSystem authority contract を持ち、automatic Git の暗黙代替にはなりません。",
    )
    replace_regex(
        path,
        r"## Approved Host current status\n.*?(?=\n## 主な機能)",
        """## Approved Host current status

Approved Host の production route は immutable runtime と LocalSystem authority service の両方を前提にします。`approved_host_enabled=true` や `request_host_command` surface、pending／approved row だけでは execution availability を意味しません。

通常の導入順序は `install-approved-host-runtime.ps1` → non-elevated `verify-approved-host-runtime.ps1` → elevated `install-approved-host-authority.ps1` → non-elevated `verify-approved-host-authority.ps1` です。WLMCP-R2-001 を fixed と判定する前に `verify-approved-host-authority-abnormal.ps1` の Arm／KillAndRestart／Check も通します。

`session_info()` の `available=true` は immutable runtime と authenticated authority service の current preflight が通ったことだけを意味します。Hosted CI や service health を full capability の `live_verified`／`windows_live_verified` へ昇格しません。この branch の release status は Windows live verification pending です。

詳細は `docs/APPROVED_HOST_RUNTIME.md` と `docs/APPROVED_HOST_PRODUCT_INVARIANT.md` を参照してください。
""",
    )
    replace_exact(
        path,
        "| Sandbox 外の Windows 権限／network が必要な処理 | current v1 では unavailable | `request_host_command` は compatibility staging のみ |",
        "| Sandbox 外の Windows 権限／network が必要な eligible 処理 | Approved Host | `request_host_command` → local approval → LocalSystem monitor／ordinary user child |",
    )


def patch_verification() -> None:
    path = "VERIFICATION.md"
    prefix = "# 検証記録\n\n"
    text = _read(path)
    if not text.startswith(prefix):
        raise RuntimeError("VERIFICATION.md header changed")
    if "## 2026-08-27 WLMCP-R2-001 LocalSystem authority remediation — LIVE VERIFICATION PENDING" in text:
        raise RuntimeError("VERIFICATION.md current R2-001 section already exists")
    current = '''## 2026-08-27 WLMCP-R2-001 LocalSystem authority remediation — LIVE VERIFICATION PENDING

### Current verdict

- finding は `High / valid` のまま。旧 same-user monitor／postflight architecture の bypass は成立する。
- 2026-08-27 の Approved Host 全面 fail-closed は temporary exploit containment／product regression の historical record であり、trusted operator は final remediation として拒否した。
- current branch は monitor／postflight worker を LocalSystem service へ移し、実 command を verified non-elevated requester-user token で起動する root-remediation candidate を実装する。
- ProgramData の LocalSystem-owned immutable active latch、service epoch、normal-return＋verified-postflight completion proof、requester-user WMI process census、runtime-user monitor-stop denial を追加した。
- GitHub Hosted Windows の Ruff／compileall／pytest は必要な regression evidence だが、SCM／ProgramData ACL、SYSTEM process/thread/token rights、requester-token child、worker kill／service restart を証明する Windows live evidence ではない。
- `verify-approved-host-authority.ps1` normal path と `verify-approved-host-authority-abnormal.ps1` Arm／KillAndRestart／Check が実 PC で成功するまで status は `valid / remediation implemented / Windows live verification pending`。その前に `fixed`／`closed` と記録したり main へ merge したりしない。

### Candidate architecture / regression scope

- production service: `WindowsLocalMCPApprovedHost` / LocalSystem / protected SCM DACL。
- durable state: `%ProgramData%\\WindowsLocalMCP\\ApprovedHostAuthority` / LocalSystem owner / protected SYSTEM+Administrators DACL。
- final command: pipe requester PID／create-time／SID／non-elevated token を検証し `CreateProcessAsUserW`。SYSTEM child へ昇格しない。
- Job Object: suspended child を SYSTEM worker Job へ assign 後 resume。
- WMI/CIM: SYSTEM current-user census へ誤変換せず、元 requester-user PID／create-time baseline を postflight まで追跡。
- completion: child start 後は expected control-plane postflight と正常 `run_operation()` return の両方がなければ proof を作らない。
- restart: active latch がある service start は recovery_required。旧 service epoch proof は受理しない。
- runtime-user `stop_job`／pipe cancel は active Host monitor を停止できない。
- legacy pending approval は abnormal Host latch 後に current generation／authority gate を bypassできないことを mandatory abnormal live verification に含める。

'''
    text = prefix + current + text[len(prefix):]
    text = text.replace(
        "## 2026-08-27 WLMCP-R2-001 remediation — CLOSED",
        "## 2026-08-27 historical WLMCP-R2-001 capability-reduction record — SUPERSEDED",
        1,
    )
    text = text.replace(
        "- 下記 Security Scan Round 2 の `WLMCP-R2-001 | High | unresolved / release blocker` は scan 時点の履歴として残すが、この節が current status を supersede する。current v1 に対する WLMCP-R2-001 は `fixed by capability reduction / closed` とする。",
        "- 下記 Security Scan Round 2 の `WLMCP-R2-001 | High | unresolved / release blocker` と本 historical section は各時点の記録として残す。current status は上記 LocalSystem authority remediation section が supersede し、旧 `fixed by capability reduction / closed` は final product remediation の判定には使用しない。",
        1,
    )
    marker = "### 判定\n\n"
    old_heading = "## 2026-08-27 historical WLMCP-R2-001 capability-reduction record — SUPERSEDED\n\n"
    note = "この節は total fail-closed mitigation を採用した時点の履歴です。以下の `current v1`／`closed` 表現は上記 current remediation section により supersede されています。\n\n"
    text = text.replace(old_heading + marker, old_heading + note + marker, 1)
    _write(path, text)


def patch_ci_workflow() -> None:
    path = ".github/workflows/finalize-atomic-commit.yml"
    old = """      - name: Full pytest
        run: python -m pytest
"""
    new = """      - name: Focused WLMCP-R2-001 authority regressions
        run: >-
          python -m pytest -q
          tests/test_approved_host_authority_state.py
          tests/test_approved_host_hardened_state.py
          tests/test_approved_host_fail_closed.py
          tests/test_approved_host_stop_boundary.py
          tests/test_approved_host_service_entry.py
          tests/test_approved_host_crash_recovery.py
          tests/test_approved_host_audit_integrity.py
          tests/test_approval_execution_integration.py

      - name: Full pytest
        run: python -m pytest
"""
    replace_exact(path, old, new)


def assert_docs() -> None:
    forbidden = {
        "SECURITY_CONTRACT.md": [
            "current v1 の Approved Host execution は capability reduction として\nfail closed に固定",
            "current v1 では Approved Host execution capability 自体を fail closed にします",
        ],
        "SPEC.md": [
            "current v1 deliberately makes the Approved Host execution route unavailable",
            "Current v1 does not launch Approved Host workers",
            "compatibility/configuration surface only in current v1; execution is unavailable",
        ],
        "README.md": [
            "current v1 の execution route は WLMCP-R2-001 の capability reduction により unavailable",
            "Approved Host は current v1 では runtime が immutable かどうかにかかわらず execution unavailable",
            "production gate は worker spawn 前に必ず fail closed",
        ],
    }
    for path, phrases in forbidden.items():
        text = _read(path)
        for phrase in phrases:
            if phrase in text:
                raise RuntimeError(f"{path}: stale Approved Host current-state phrase remains: {phrase}")


if __name__ == "__main__":
    patch_python()
    patch_security_contract()
    patch_spec()
    patch_readme()
    patch_verification()
    patch_ci_workflow()
    assert_docs()
