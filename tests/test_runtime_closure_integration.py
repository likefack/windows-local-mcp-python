from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from windows_local_mcp import runtime_trust

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_PACKAGE = _REPO_ROOT / "src" / "windows_local_mcp"

_PROBE = r"""
import json
import sys
from pathlib import Path

startup_sys_path = [
    str(Path(value).resolve(strict=False))
    for value in sys.path
    if value
]

from windows_local_mcp import runtime_immutability, runtime_trust

inventory = runtime_trust.build_runtime_trust_inventory()
directories, ancestors, files, _ = runtime_immutability._runtime_paths(inventory=inventory)
closure_paths = sorted(
    {
        *(str(path.resolve(strict=True)) for path in directories),
        *(str(path.resolve(strict=True)) for path in ancestors),
        *(str(path.resolve(strict=True)) for path in files),
    }
)

print(
    json.dumps(
        {
            "isolated": int(sys.flags.isolated),
            "dont_write_bytecode": bool(sys.dont_write_bytecode),
            "startup_sys_path": startup_sys_path,
            "runtime_module": str(Path(runtime_trust.__file__).resolve(strict=True)),
            "prefix": str(Path(sys.prefix).resolve(strict=True)),
            "base_prefix": str(Path(sys.base_prefix).resolve(strict=True)),
            "closure_paths": closure_paths,
        }
    )
)
"""


def _is_inside(candidate: Path, parent: Path) -> bool:
    try:
        candidate.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except ValueError:
        return False


def _contains_dev_tmp(path: Path) -> bool:
    return any(part.casefold() == ".dev-tmp" for part in path.parts)


def _external_temp_parent() -> Path:
    candidates = (Path(tempfile.gettempdir()), _REPO_ROOT.parent)
    for candidate in candidates:
        resolved = candidate.resolve(strict=False)
        if _is_inside(resolved, _REPO_ROOT) or _contains_dev_tmp(resolved):
            continue
        if resolved.is_dir() and os.access(resolved, os.W_OK):
            return resolved
    pytest.skip("no writable temporary parent exists outside the mutable checkout")


def _outside_checkout_python() -> Path:
    raw_candidates = (
        getattr(sys, "_base_executable", None),
        sys.executable,
    )
    for value in raw_candidates:
        if not value:
            continue
        candidate = Path(value).resolve(strict=True)
        if _is_inside(candidate, _REPO_ROOT) or _contains_dev_tmp(candidate):
            continue
        return candidate
    pytest.skip("no Python interpreter is available outside the mutable checkout")


def _copy_distribution_closure(staging_root: Path, site_root: Path) -> None:
    for distribution in runtime_trust._distribution_closure():
        listed = distribution.files
        if listed is None:
            pytest.fail(
                "trusted dependency has no installed file manifest: "
                f"{distribution.metadata.get('Name')}"
            )
        for relative in listed:
            relative_path = Path(str(relative))
            if relative_path.is_absolute():
                pytest.fail(f"trusted dependency manifest contains an absolute path: {relative}")

            source = Path(distribution.locate_file(relative))
            if not source.exists():
                pytest.fail(f"trusted dependency file disappeared: {source}")

            destination = (site_root / relative_path).resolve(strict=False)
            if not _is_inside(destination, staging_root):
                pytest.fail(
                    "trusted dependency manifest escapes the integration staging root: "
                    f"{relative}"
                )

            if source.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)


def _create_external_runtime(python: Path, staging_root: Path) -> tuple[Path, Path]:
    runtime_home = staging_root / "runtime"
    create = subprocess.run(
        [
            str(python),
            "-I",
            "-B",
            "-m",
            "venv",
            "--without-pip",
            str(runtime_home),
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    if create.returncode != 0:
        pytest.fail(f"could not create isolated integration venv: {create.stderr}")

    runtime_python = (
        runtime_home / "Scripts" / "python.exe"
        if os.name == "nt"
        else runtime_home / "bin" / "python"
    ).resolve(strict=True)

    query = subprocess.run(
        [
            str(runtime_python),
            "-I",
            "-B",
            "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))",
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if query.returncode != 0:
        pytest.fail(f"could not resolve isolated integration site-packages: {query.stderr}")
    site_root = Path(query.stdout.strip()).resolve(strict=True)
    return runtime_python, site_root


@pytest.mark.skipif(os.name != "nt", reason="Approved Host runtime closure is Windows-only")
def test_isolated_subprocess_runtime_closure_excludes_checkout_and_dev_tmp() -> None:
    python = _outside_checkout_python()
    temp_parent = _external_temp_parent()

    dev_tmp_parent = _REPO_ROOT / ".dev-tmp" / "pytest" / "runtime-closure-subprocess"
    dev_tmp_parent.mkdir(parents=True, exist_ok=True)
    probe_cwd = Path(tempfile.mkdtemp(prefix="probe-", dir=dev_tmp_parent))

    try:
        with tempfile.TemporaryDirectory(
            prefix="wlmcp-runtime-closure-",
            dir=temp_parent,
        ) as raw_staging_root:
            staging_root = Path(raw_staging_root).resolve(strict=True)
            runtime_python, site_root = _create_external_runtime(python, staging_root)

            shutil.copytree(
                _SOURCE_PACKAGE,
                site_root / "windows_local_mcp",
                copy_function=shutil.copyfile,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            _copy_distribution_closure(staging_root, site_root)

            env = os.environ.copy()
            env["PYTHONPATH"] = os.pathsep.join(
                (str(_REPO_ROOT / "src"), str(probe_cwd))
            )
            result = subprocess.run(
                [str(runtime_python), "-I", "-B", "-c", _PROBE],
                cwd=probe_cwd,
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=120,
            )

            assert result.returncode == 0, result.stderr
            payload = json.loads(result.stdout)
            assert payload["isolated"] == 1
            assert payload["dont_write_bytecode"] is True

            runtime_module = Path(payload["runtime_module"]).resolve(strict=True)
            runtime_prefix = Path(payload["prefix"]).resolve(strict=True)
            assert _is_inside(runtime_module, site_root)
            assert _is_inside(runtime_prefix, staging_root)

            contaminated: list[str] = []
            for raw_path in (
                *payload["startup_sys_path"],
                *payload["closure_paths"],
            ):
                path = Path(raw_path).resolve(strict=False)
                if _is_inside(path, _REPO_ROOT) or _contains_dev_tmp(path):
                    contaminated.append(str(path))

            assert contaminated == []
    finally:
        shutil.rmtree(probe_cwd, ignore_errors=True)
