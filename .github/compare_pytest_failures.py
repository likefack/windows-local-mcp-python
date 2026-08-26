from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def failure_ids(path: Path) -> set[str]:
    root = ET.parse(path).getroot()
    result: set[str] = set()
    for case in root.iter("testcase"):
        if case.find("failure") is None and case.find("error") is None:
            continue
        classname = case.attrib.get("classname", "")
        name = case.attrib.get("name", "")
        result.add(f"{classname}::{name}")
    return result


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: compare_pytest_failures.py BASELINE.xml CANDIDATE.xml")
    baseline = failure_ids(Path(sys.argv[1]))
    candidate = failure_ids(Path(sys.argv[2]))
    added = candidate - baseline
    fixed = baseline - candidate
    print(f"baseline failures: {len(baseline)}")
    for item in sorted(baseline):
        print(f"  baseline: {item}")
    print(f"candidate failures: {len(candidate)}")
    for item in sorted(candidate):
        print(f"  candidate: {item}")
    if fixed:
        print("candidate-fixed failures:")
        for item in sorted(fixed):
            print(f"  fixed: {item}")
    if added:
        print("new candidate failures:")
        for item in sorted(added):
            print(f"  NEW: {item}")
        return 1
    print("candidate introduced no new pytest failures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
