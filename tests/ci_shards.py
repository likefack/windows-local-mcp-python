from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence

_RUNTIME_CLOSURE_FILE = "tests/test_runtime_closure_integration.py"


def _collect_nodeids(args: Sequence[str]) -> set[str]:
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        shell=False,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise RuntimeError(f"pytest collection failed for args={list(args)!r}")

    nodeids = {
        line.strip().replace("\\", "/")
        for line in completed.stdout.splitlines()
        if line.strip().replace("\\", "/").startswith("tests/") and "::" in line
    }
    if not nodeids:
        raise RuntimeError(f"pytest collection returned no test nodeids for args={list(args)!r}")
    return nodeids


def main() -> int:
    full = _collect_nodeids(())
    core = _collect_nodeids((f"--ignore={_RUNTIME_CLOSURE_FILE}",))
    runtime_closure = _collect_nodeids((_RUNTIME_CLOSURE_FILE,))

    overlap = core & runtime_closure
    missing = full - (core | runtime_closure)
    extra = (core | runtime_closure) - full

    failures: list[str] = []
    if overlap:
        failures.append(
            "core/runtime_closure overlap:\n  " + "\n  ".join(sorted(overlap))
        )
    if missing:
        failures.append("tests missing from CI shards:\n  " + "\n  ".join(sorted(missing)))
    if extra:
        failures.append("CI shard tests absent from full collection:\n  " + "\n  ".join(sorted(extra)))

    if failures:
        sys.stderr.write("pytest shard completeness check failed\n\n")
        sys.stderr.write("\n\n".join(failures) + "\n")
        return 1

    print(
        "pytest shard completeness passed: "
        f"full={len(full)} core={len(core)} runtime_closure={len(runtime_closure)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
