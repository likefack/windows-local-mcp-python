from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one match, found {count}: {old[:80]!r}")
    target.write_text(text.replace(old, new), encoding="utf-8")


def replace_n(path: str, old: str, new: str, expected: int) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != expected:
        raise RuntimeError(f"{path}: expected {expected} matches, found {count}: {old[:80]!r}")
    target.write_text(text.replace(old, new), encoding="utf-8")


PATHS = "src/windows_local_mcp/paths.py"
SERVER = "src/windows_local_mcp/server.py"
HISTORY = "src/windows_local_mcp/workspace_history.py"
APPROVAL = "src/windows_local_mcp/approval.py"

replace_once(
    PATHS,
    "_FILE_READ_ATTRIBUTES = 0x00000080\n_FILE_SHARE_READ = 0x00000001\n",
    "_GENERIC_READ = 0x80000000\n_FILE_READ_ATTRIBUTES = 0x00000080\n_FILE_SHARE_READ = 0x00000001\n_FILE_BEGIN = 0\n_READ_CHUNK_BYTES = 1024 * 1024\n",
)

replace_once(
    PATHS,
    '''class _WindowsHandleLease:\n    def __init__(self, handles: list[Any]) -> None:\n        self._handles = handles\n\n    def close(self) -> None:\n        handles, self._handles = self._handles, []\n        if not handles or os.name != "nt":\n            return\n        try:\n            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)\n        except OSError:\n            return\n        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]\n        kernel32.CloseHandle.restype = wintypes.BOOL\n        for handle in reversed(handles):\n            kernel32.CloseHandle(handle)\n''',
    '''class _WindowsHandleLease:\n    def __init__(self, handles: list[Any], *, readable_final: bool = False) -> None:\n        self._handles = handles\n        self._readable_final = readable_final\n\n    def read_final_bytes(self, max_bytes: int) -> bytes:\n        if max_bytes < 0:\n            raise ValueError("max_bytes must be non-negative")\n        if os.name != "nt" or not self._handles or not self._readable_final:\n            raise RuntimeError("verified Windows file handle is not readable")\n        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)\n        kernel32.GetFileInformationByHandle.argtypes = [\n            wintypes.HANDLE,\n            ctypes.POINTER(_ByHandleFileInformation),\n        ]\n        kernel32.GetFileInformationByHandle.restype = wintypes.BOOL\n        kernel32.SetFilePointerEx.argtypes = [\n            wintypes.HANDLE,\n            ctypes.c_longlong,\n            ctypes.POINTER(ctypes.c_longlong),\n            wintypes.DWORD,\n        ]\n        kernel32.SetFilePointerEx.restype = wintypes.BOOL\n        kernel32.ReadFile.argtypes = [\n            wintypes.HANDLE,\n            wintypes.LPVOID,\n            wintypes.DWORD,\n            ctypes.POINTER(wintypes.DWORD),\n            wintypes.LPVOID,\n        ]\n        kernel32.ReadFile.restype = wintypes.BOOL\n        handle = self._handles[-1]\n        information = _ByHandleFileInformation()\n        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(information)):\n            raise OSError(get_last_error(), "GetFileInformationByHandle failed")\n        size = (int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow)\n        if size > max_bytes:\n            raise ValueError(f"file exceeds byte limit: {size} > {max_bytes}")\n        if not kernel32.SetFilePointerEx(handle, 0, None, _FILE_BEGIN):\n            raise OSError(get_last_error(), "SetFilePointerEx failed")\n        output = bytearray()\n        buffer = ctypes.create_string_buffer(_READ_CHUNK_BYTES)\n        while True:\n            read = wintypes.DWORD()\n            if not kernel32.ReadFile(handle, buffer, len(buffer), ctypes.byref(read), None):\n                raise OSError(get_last_error(), "ReadFile failed")\n            if not read.value:\n                return bytes(output)\n            output.extend(buffer.raw[: read.value])\n            if len(output) > max_bytes:\n                raise RuntimeError("verified file exceeded its byte bound while reading")\n\n    def close(self) -> None:\n        handles, self._handles = self._handles, []\n        if not handles or os.name != "nt":\n            return\n        try:\n            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)\n        except OSError:\n            return\n        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]\n        kernel32.CloseHandle.restype = wintypes.BOOL\n        for handle in reversed(handles):\n            kernel32.CloseHandle(handle)\n''',
)

replace_once(
    PATHS,
    '''class _HeldPath(_PathBase):\n    __slots__ = ("__weakref__", "_lease_finalizer", "_write_intent")\n\n    def __new__(cls, *parts: Any) -> Self:\n        instance = super().__new__(cls, *parts)\n        instance._lease_finalizer = None\n        instance._write_intent = False\n        return instance\n''',
    '''class _HeldPath(_PathBase):\n    __slots__ = ("__weakref__", "_lease", "_lease_finalizer", "_write_intent")\n\n    def __new__(cls, *parts: Any) -> Self:\n        instance = super().__new__(cls, *parts)\n        instance._lease = None\n        instance._lease_finalizer = None\n        instance._write_intent = False\n        return instance\n''',
)
replace_once(
    PATHS,
    '''        instance = cls(path)\n        instance._write_intent = write_intent\n        instance._lease_finalizer = weakref.finalize(instance, lease.close)\n''',
    '''        instance = cls(path)\n        instance._lease = lease\n        instance._write_intent = write_intent\n        instance._lease_finalizer = weakref.finalize(instance, lease.close)\n''',
)
replace_once(
    PATHS,
    '''def release_verified_hold(path: Path) -> None:\n    """Release any explicit verified-path lease after its guarded interval ends."""\n    _release_held_path(path)\n\n\ndef _windows_component_handles(\n''',
    '''def release_verified_hold(path: Path) -> None:\n    """Release any explicit verified-path lease after its guarded interval ends."""\n    _release_held_path(path)\n\n\ndef read_verified_bytes(path: Path, max_bytes: int) -> bytes:\n    """Read workspace bytes from the exact file object validated on Windows."""\n    if max_bytes < 0:\n        raise ValueError("max_bytes must be non-negative")\n    if os.name == "nt":\n        if not isinstance(path, _HeldPath) or path._lease is None:\n            raise RuntimeError("Windows workspace read requires a verified file handle")\n        return path._lease.read_final_bytes(max_bytes)\n\n    # Non-Windows support exists for tests and development only. Windows is the\n    # security-supported production route for this project.\n    size = path.stat().st_size\n    if size > max_bytes:\n        raise ValueError(f"file exceeds byte limit: {size} > {max_bytes}")\n    with path.open("rb") as source:\n        data = source.read(max_bytes + 1)\n    if len(data) > max_bytes:\n        raise ValueError(f"file exceeds byte limit: {len(data)} > {max_bytes}")\n    return data\n\n\ndef _windows_component_handles(\n''',
)
replace_once(
    PATHS,
    '''    allow_hardlinks: bool,\n    write_intent: bool = False,\n    final_share_write: bool = False,\n) -> Path:\n''',
    '''    allow_hardlinks: bool,\n    write_intent: bool = False,\n    final_share_write: bool = False,\n    final_read_data: bool = False,\n) -> Path:\n''',
)
replace_once(
    PATHS,
    '''            handle = kernel32.CreateFileW(\n                str(current),\n                _FILE_READ_ATTRIBUTES,\n                share_mode,\n''',
    '''            desired_access = _FILE_READ_ATTRIBUTES\n            if final and final_read_data:\n                desired_access |= _GENERIC_READ\n            handle = kernel32.CreateFileW(\n                str(current),\n                desired_access,\n                share_mode,\n''',
)
replace_once(
    PATHS,
    '''        lease = _WindowsHandleLease(handles)\n        handles = []\n        return _HeldPath.attach(lexical, lease, write_intent=write_intent)\n''',
    '''        lease = _WindowsHandleLease(handles, readable_final=final_read_data)\n        handles = []\n        return _HeldPath.attach(lexical, lease, write_intent=write_intent)\n''',
)
replace_once(
    PATHS,
    '''def hold_verified_path(\n    path: str | Path,\n    *,\n    allow_directory: bool = False,\n    allow_hardlinks: bool = False,\n) -> Path:\n''',
    '''def hold_verified_path(\n    path: str | Path,\n    *,\n    allow_directory: bool = False,\n    allow_hardlinks: bool = False,\n    readable: bool = False,\n) -> Path:\n''',
)
replace_once(
    PATHS,
    '''            lexical,\n            allow_directory=allow_directory,\n            allow_hardlinks=allow_hardlinks,\n        )\n''',
    '''            lexical,\n            allow_directory=allow_directory,\n            allow_hardlinks=allow_hardlinks,\n            final_read_data=readable,\n        )\n''',
)
replace_once(
    PATHS,
    '''            allow_directory=False,\n            allow_hardlinks=False,\n            write_intent=True,\n        )\n''',
    '''            allow_directory=False,\n            allow_hardlinks=False,\n            write_intent=True,\n            final_read_data=True,\n        )\n''',
)
replace_once(
    PATHS,
    '''        access: str = "read",\n        hold_identity: bool = True,\n    ) -> Path:\n''',
    '''        access: str = "read",\n        hold_identity: bool = True,\n        readable: bool | None = None,\n    ) -> Path:\n''',
)
replace_once(
    PATHS,
    '''                return hold_verified_path(\n                    resolved,\n                    allow_directory=False,\n                    allow_hardlinks=False,\n                )\n''',
    '''                return hold_verified_path(\n                    resolved,\n                    allow_directory=False,\n                    allow_hardlinks=False,\n                    readable=access == "read" if readable is None else readable,\n                )\n''',
)
replace_once(
    PATHS,
    '''        temporary: Path | None = None\n        try:\n''',
    '''        # Non-Windows os.replace fallback is retained only for test portability;\n        # Windows TxF is the security-supported production commit boundary.\n        temporary: Path | None = None\n        try:\n''',
)

replace_once(
    SERVER,
    "from .paths import PathIdentity, Workspace, release_verified_hold\n",
    "from .paths import PathIdentity, Workspace, read_verified_bytes, release_verified_hold\n",
)
replace_once(
    SERVER,
    '''    verified = runtime.workspace.resolve_existing(\n        path, allow_directory=False, access="write"\n    )\n''',
    '''    verified = runtime.workspace.resolve_existing(\n        path, allow_directory=False, access="write", readable=True\n    )\n''',
)
replace_once(
    SERVER,
    '''        if identity.size != len(expected) or verified.read_bytes() != expected:\n''',
    '''        if identity.size != len(expected) or read_verified_bytes(verified, len(expected)) != expected:\n''',
)
replace_once(
    SERVER,
    '''    if current_identity.size != len(after) or current.read_bytes() != after:\n''',
    '''    if current_identity.size != len(after) or read_verified_bytes(current, len(after)) != after:\n''',
)
replace_once(
    SERVER,
    '''    restored = runtime.workspace.resolve_existing(path, allow_directory=False, access="write")\n''',
    '''    restored = runtime.workspace.resolve_existing(\n        path, allow_directory=False, access="write", readable=True\n    )\n''',
)
replace_once(
    SERVER,
    '''        if restored_identity is None or restored.read_bytes() != before:\n''',
    '''        if restored_identity is None or read_verified_bytes(restored, len(before)) != before:\n''',
)
replace_once(
    SERVER,
    '''                        "filesystem_identity_lock_replace": {\n                            "status": "verified",\n                            "evidence": "startup filesystem identity/lock/replace probe",\n                        },\n''',
    '''                        "same_handle_workspace_read": {\n                            "status": "verified" if os.name == "nt" else "unsupported",\n                            "production_supported": os.name == "nt",\n                            "evidence": (\n                                "validated Windows file HANDLE is retained and consumed directly by ReadFile"\n                                if os.name == "nt"\n                                else "non-Windows pathname read fallback is test-only"\n                            ),\n                        },\n                        "transactional_workspace_commit": {\n                            "status": "verified" if os.name == "nt" else "unsupported",\n                            "production_supported": os.name == "nt",\n                            "evidence": (\n                                "startup TxF isolation/commit probe plus CAS-bound transactional writer"\n                                if os.name == "nt"\n                                else "non-Windows os.replace fallback is test-only"\n                            ),\n                        },\n''',
)
replace_once(
    SERVER,
    '''        file_path = runtime.workspace.resolve_existing(path, allow_directory=False)\n        text = read_text_limited(file_path, runtime.settings.max_text_file_bytes)\n        raw = text.encode("utf-8")\n''',
    '''        file_path = runtime.workspace.resolve_existing(path, allow_directory=False)\n        raw = read_verified_bytes(file_path, runtime.settings.max_text_file_bytes)\n        text = raw.decode("utf-8")\n''',
)
replace_once(
    SERVER,
    '''        image_path = runtime.workspace.resolve_existing(path, allow_directory=False)\n        size = image_path.stat().st_size\n        if size > runtime.settings.max_image_bytes:\n            raise ValueError("image byte limit exceeded")\n        image_format = {\n''',
    '''        image_path = runtime.workspace.resolve_existing(path, allow_directory=False)\n        image_format = {\n''',
)
replace_once(
    SERVER,
    '''        if image_format is None:\n            raise ValueError("unsupported image format")\n        data = image_path.read_bytes()\n        if len(data) != size:\n            raise RuntimeError("image changed while reading")\n''',
    '''        if image_format is None:\n            raise ValueError("unsupported image format")\n        data = read_verified_bytes(image_path, runtime.settings.max_image_bytes)\n        size = len(data)\n''',
)
replace_once(
    SERVER,
    '''            if target.exists():\n                source_size = target.stat().st_size\n                if source_size > runtime.settings.max_structured_file_bytes:\n                    raise ValueError("structured file exceeds max_structured_file_bytes")\n                before = target.read_bytes()\n            else:\n''',
    '''            if target.exists():\n                if target_identity is None:\n                    raise RuntimeError("structured source disappeared before read")\n                if target_identity.size > runtime.settings.max_structured_file_bytes:\n                    raise ValueError("structured file exceeds max_structured_file_bytes")\n                before = read_verified_bytes(\n                    target, runtime.settings.max_structured_file_bytes\n                )\n            else:\n''',
)
replace_once(
    SERVER,
    '''        size = target.stat().st_size\n        if size > runtime.settings.max_structured_file_bytes:\n            raise ValueError("structured file exceeds max_structured_file_bytes")\n        data = target.read_bytes()\n        runtime.workspace.revalidate_for_replace(\n            target,\n            parent_identity=parent_identity,\n            target_identity=identity,\n        )\n        if target.read_bytes() != data:\n            raise RuntimeError("source changed while preparing the processing artifact")\n        return target, data, True\n''',
    '''        if identity is None:\n            raise RuntimeError("source disappeared before processing read")\n        if identity.size > runtime.settings.max_structured_file_bytes:\n            raise ValueError("structured file exceeds max_structured_file_bytes")\n        data = read_verified_bytes(target, runtime.settings.max_structured_file_bytes)\n        runtime.workspace.revalidate_for_replace(\n            target,\n            parent_identity=parent_identity,\n            target_identity=identity,\n        )\n        return target, data, True\n''',
)
replace_once(
    SERVER,
    '''        source = runtime.workspace.resolve_existing(path, allow_directory=False)\n        if source.stat().st_size > runtime.settings.max_structured_file_bytes:\n            raise RuntimeError("bound source exceeds max_structured_file_bytes")\n        if sha256_bytes(source.read_bytes()) != expected:\n            raise RuntimeError(f"bound source changed before commit: {path}")\n''',
    '''        source = runtime.workspace.resolve_existing(path, allow_directory=False)\n        identity = runtime.workspace.identity(source)\n        if identity is None or identity.size > runtime.settings.max_structured_file_bytes:\n            raise RuntimeError("bound source exceeds max_structured_file_bytes")\n        if sha256_bytes(\n            read_verified_bytes(source, runtime.settings.max_structured_file_bytes)\n        ) != expected:\n            raise RuntimeError(f"bound source changed before commit: {path}")\n''',
)
replace_once(
    SERVER,
    '''        source = runtime.workspace.resolve_existing(path, allow_directory=False)\n        if source.stat().st_size > runtime.settings.max_structured_file_bytes:\n            raise ValueError("structured file exceeds max_structured_file_bytes")\n        data = source.read_bytes()\n''',
    '''        source = runtime.workspace.resolve_existing(path, allow_directory=False)\n        identity = runtime.workspace.identity(source)\n        if identity is None or identity.size > runtime.settings.max_structured_file_bytes:\n            raise ValueError("structured file exceeds max_structured_file_bytes")\n        data = read_verified_bytes(source, runtime.settings.max_structured_file_bytes)\n''',
)
replace_once(
    SERVER,
    '''        if archive.stat().st_size > runtime.settings.max_structured_file_bytes:\n            raise ValueError("structured file exceeds max_structured_file_bytes")\n        payload = read_zip_entry(archive.read_bytes(), entry, runtime.settings)\n''',
    '''        archive_identity = runtime.workspace.identity(archive)\n        if archive_identity is None or archive_identity.size > runtime.settings.max_structured_file_bytes:\n            raise ValueError("structured file exceeds max_structured_file_bytes")\n        payload = read_zip_entry(\n            read_verified_bytes(archive, runtime.settings.max_structured_file_bytes),\n            entry,\n            runtime.settings,\n        )\n''',
)
replace_once(
    SERVER,
    '''def _copy_source_to_reserved_snapshot(source: Path, destination: Path) -> tuple[str, int]:\n    digest = hashlib.sha256()\n    total = 0\n    limit = runtime.settings.max_structured_file_bytes\n    with source.open("rb") as input_file, destination.open("r+b") as output_file:\n        output_file.seek(0)\n        while chunk := input_file.read(1024 * 1024):\n            total += len(chunk)\n            if total > limit:\n                raise ValueError("structured file exceeds max_structured_file_bytes")\n            output_file.write(chunk)\n            digest.update(chunk)\n        output_file.truncate(total)\n        output_file.flush()\n        os.fsync(output_file.fileno())\n    return digest.hexdigest(), total\n''',
    '''def _copy_source_to_reserved_snapshot(source: Path, destination: Path) -> tuple[str, int]:\n    data = read_verified_bytes(source, runtime.settings.max_structured_file_bytes)\n    with destination.open("r+b") as output_file:\n        output_file.seek(0)\n        output_file.write(data)\n        output_file.truncate(len(data))\n        output_file.flush()\n        os.fsync(output_file.fileno())\n    return sha256_bytes(data), len(data)\n''',
)
replace_once(
    SERVER,
    '''            current_sha, current_bytes = sha256_file(\n                current, max_bytes=runtime.settings.max_structured_file_bytes\n            )\n''',
    '''            current_data = read_verified_bytes(\n                current, runtime.settings.max_structured_file_bytes\n            )\n            current_sha, current_bytes = sha256_bytes(current_data), len(current_data)\n''',
)
replace_once(
    SERVER,
    '''            if source.stat().st_size != size or size > runtime.settings.max_structured_file_bytes:\n                raise RuntimeError("source changed during transfer; begin a new download")\n            data = source.read_bytes()\n''',
    '''            source_identity = runtime.workspace.identity(source)\n            if (\n                source_identity is None\n                or source_identity.size != size\n                or size > runtime.settings.max_structured_file_bytes\n            ):\n                raise RuntimeError("source changed during transfer; begin a new download")\n            data = read_verified_bytes(source, runtime.settings.max_structured_file_bytes)\n''',
)
replace_once(
    SERVER,
    '''            if target.stat().st_size > runtime.settings.max_structured_file_bytes:\n                raise ValueError("structured file exceeds max_structured_file_bytes")\n            if sha256_bytes(target.read_bytes()) != expected_sha256:\n''',
    '''            target_identity = runtime.workspace.identity(target)\n            if target_identity is None or target_identity.size > runtime.settings.max_structured_file_bytes:\n                raise ValueError("structured file exceeds max_structured_file_bytes")\n            if sha256_bytes(\n                read_verified_bytes(target, runtime.settings.max_structured_file_bytes)\n            ) != expected_sha256:\n''',
)
replace_once(
    SERVER,
    '''            previous_bytes = target.read_bytes() if target.exists() else b""\n''',
    '''            previous_bytes = (\n                read_verified_bytes(\n                    target,\n                    max(\n                        runtime.settings.max_text_file_bytes,\n                        runtime.settings.max_backup_bytes,\n                    ),\n                )\n                if target.exists()\n                else b""\n            )\n''',
)

replace_once(
    HISTORY,
    "from .paths import Workspace\n",
    "from .paths import Workspace, read_verified_bytes\n",
)
replace_once(
    HISTORY,
    '''                    verified = workspace.resolve_existing(str(relative), access="write")\n''',
    '''                    verified = workspace.resolve_existing(\n                        str(relative), access="write", readable=True\n                    )\n''',
)
replace_once(
    HISTORY,
    '''                    data = verified.read_bytes()\n''',
    '''                    data = read_verified_bytes(\n                        verified, settings.approval_manifest_max_bytes\n                    )\n''',
)
replace_once(
    HISTORY,
    '''            verified = workspace.resolve_existing(\n                relative, allow_directory=False, access="write"\n            )\n''',
    '''            verified = workspace.resolve_existing(\n                relative, allow_directory=False, access="write", readable=True\n            )\n''',
)
replace_once(
    HISTORY,
    '''            data = verified.read_bytes()\n            workspace.revalidate_for_replace(\n                verified,\n                parent_identity=parent_identity,\n                target_identity=target_identity,\n            )\n            if verified.stat().st_size != len(data) or verified.read_bytes() != data:\n                raise RuntimeError(f"scoped checkpoint target changed while read: {relative}")\n''',
    '''            data = read_verified_bytes(verified, settings.approval_manifest_max_bytes)\n            workspace.revalidate_for_replace(\n                verified,\n                parent_identity=parent_identity,\n                target_identity=target_identity,\n            )\n            if target_identity.size != len(data):\n                raise RuntimeError(f"scoped checkpoint target changed while read: {relative}")\n''',
)
replace_once(
    HISTORY,
    '''            verified = workspace.resolve_existing(\n                normalized, allow_directory=False, access="write"\n            )\n''',
    '''            verified = workspace.resolve_existing(\n                normalized, allow_directory=False, access="write", readable=True\n            )\n''',
)
replace_once(
    HISTORY,
    '''            data = verified.read_bytes()\n            workspace.revalidate_for_replace(\n                verified,\n                parent_identity=parent_identity,\n                target_identity=before_identity,\n            )\n            if verified.read_bytes() != data:\n                raise RuntimeError(\n                    f"scoped workspace verification target changed while read: {normalized}"\n                )\n''',
    '''            data = read_verified_bytes(verified, settings.approval_manifest_max_bytes)\n            workspace.revalidate_for_replace(\n                verified,\n                parent_identity=parent_identity,\n                target_identity=before_identity,\n            )\n''',
)
replace_once(
    HISTORY,
    '''                path = workspace.resolve_existing(str(relative), access="write")\n''',
    '''                path = workspace.resolve_existing(\n                    str(relative), access="write", readable=True\n                )\n''',
)
replace_once(
    HISTORY,
    '''                result[relative.as_posix()] = sha256_bytes(path.read_bytes())\n''',
    '''                result[relative.as_posix()] = sha256_bytes(\n                    read_verified_bytes(path, settings.approval_manifest_max_bytes)\n                )\n''',
)
replace_once(
    HISTORY,
    '''    if path.exists():\n        if not path.is_file() or sha256_bytes(path.read_bytes()) != expected:\n            raise RuntimeError(f"workspace file changed during restore: {relative}")\n''',
    '''    if path.exists():\n        size = path.stat().st_size\n        if not path.is_file() or sha256_bytes(read_verified_bytes(path, size)) != expected:\n            raise RuntimeError(f"workspace file changed during restore: {relative}")\n''',
)

replace_once(
    APPROVAL,
    "from .paths import Workspace, hold_verified_path\n",
    "from .paths import Workspace, hold_verified_path, read_verified_bytes\n",
)
replace_once(
    APPROVAL,
    '''            checked = hold_verified_path(source_file, allow_directory=False)\n''',
    '''            checked = hold_verified_path(\n                source_file, allow_directory=False, readable=True\n            )\n''',
)
replace_n(
    APPROVAL,
    '''            target = destination / relative_root / name\n            shutil.copy2(checked, target)\n            record = _file_record(target)\n''',
    '''            target = destination / relative_root / name\n            target.write_bytes(\n                read_verified_bytes(checked, settings.approval_manifest_max_bytes)\n            )\n            shutil.copystat(checked, target, follow_symlinks=False)\n            record = _file_record(target)\n''',
    2,
)
replace_once(
    APPROVAL,
    '''    path = hold_verified_path(\n        path,\n        allow_directory=False,\n        allow_hardlinks=allow_hardlinks,\n    )\n''',
    '''    path = hold_verified_path(\n        path,\n        allow_directory=False,\n        allow_hardlinks=allow_hardlinks,\n        readable=True,\n    )\n''',
)
replace_once(
    APPROVAL,
    '''    data = path.read_bytes()\n''',
    '''    data = read_verified_bytes(\n        path, max_bytes if max_bytes is not None else info.st_size\n    )\n''',
)
replace_once(
    APPROVAL,
    '''            inventory[str(checked)] = (sha256_bytes(checked.read_bytes()), size)\n''',
    '''            inventory[str(checked)] = (\n                sha256_bytes(\n                    read_verified_bytes(checked, settings.approval_manifest_max_bytes)\n                ),\n                size,\n            )\n''',
)

Path("tests/test_same_handle_reads.py").write_text(
    '''from __future__ import annotations\n\nimport importlib\nimport os\nimport sys\nfrom pathlib import Path\n\nimport pytest\nfrom PIL import Image as PILImage\n\nfrom windows_local_mcp import approval\nfrom windows_local_mcp.config import Settings\nfrom windows_local_mcp.paths import Workspace, read_verified_bytes\nfrom windows_local_mcp.util import sha256_bytes\nfrom windows_local_mcp.workspace_history import capture_workspace_state\n\n\ndef _workspace(tmp_path: Path) -> Workspace:\n    root = tmp_path / "workspace"\n    root.mkdir()\n    settings = Settings(\n        workspace_root=root,\n        data_dir=tmp_path / "data",\n        protect_data_dir_acl=False,\n        git_enabled=False,\n    )\n    settings.ensure_directories()\n    return Workspace(settings)\n\n\ndef _load_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):\n    root = tmp_path / "server-workspace"\n    root.mkdir()\n    data = tmp_path / "server-data"\n    config = tmp_path / "config.toml"\n    config.write_text(\n        "\\n".join(\n            [\n                f'workspace_root = "{str(root).replace(chr(92), chr(92) * 2)}"',\n                f'data_dir = "{str(data).replace(chr(92), chr(92) * 2)}"',\n                "protect_data_dir_acl = false",\n                "git_enabled = false",\n            ]\n        ),\n        encoding="utf-8",\n    )\n    monkeypatch.setenv("LOCAL_MCP_CONFIG", str(config))\n    monkeypatch.delenv("LOCAL_MCP_ROOT", raising=False)\n    sys.modules.pop("windows_local_mcp.server", None)\n    return importlib.import_module("windows_local_mcp.server"), root\n\n\n@pytest.mark.skipif(os.name != "nt", reason="same-HANDLE read is the Windows security boundary")\ndef test_verified_read_consumes_the_validation_handle_without_path_reopen(\n    tmp_path: Path, monkeypatch: pytest.MonkeyPatch\n) -> None:\n    workspace = _workspace(tmp_path)\n    target = workspace.root / "safe.txt"\n    target.write_bytes(b"safe")\n    verified = workspace.resolve_existing("safe.txt", allow_directory=False)\n    real_open = Path.open\n\n    def guarded_open(self: Path, *args, **kwargs):\n        if Path(self).resolve(strict=False) == target.resolve(strict=False):\n            raise AssertionError("verified workspace file was reopened by pathname")\n        return real_open(self, *args, **kwargs)\n\n    monkeypatch.setattr(Path, "open", guarded_open)\n    assert read_verified_bytes(verified, 1024) == b"safe"\n\n\n@pytest.mark.skipif(os.name != "nt", reason="same-HANDLE read is the Windows security boundary")\ndef test_broker_workspace_read_sinks_do_not_reopen_verified_paths(\n    tmp_path: Path, monkeypatch: pytest.MonkeyPatch\n) -> None:\n    server, root = _load_server(tmp_path, monkeypatch)\n    text = root / "note.txt"\n    text.write_bytes(b"hello\\n")\n    csv = root / "table.csv"\n    csv.write_bytes(b"a,b\\n1,2\\n")\n    artifact = root / "artifact.bin"\n    artifact.write_bytes(b"artifact")\n    image = root / "pixel.png"\n    PILImage.new("RGB", (2, 2), "white").save(image)\n    guarded = {item.resolve(strict=False) for item in (text, csv, artifact, image)}\n    real_open = Path.open\n\n    def guarded_open(self: Path, *args, **kwargs):\n        if Path(self).resolve(strict=False) in guarded:\n            raise AssertionError(f"workspace source was reopened by pathname: {self}")\n        return real_open(self, *args, **kwargs)\n\n    monkeypatch.setattr(Path, "open", guarded_open)\n\n    assert server.read_file("note.txt")["content"] == "hello"\n    server.get_image("pixel.png")\n    assert server.structured_file_inspect("table.csv")["format"] == "csv"\n    server.artifact_download_begin("artifact.bin")\n    capture_workspace_state(\n        server.runtime.settings, "same-handle-checkpoint", "before", paths={"note.txt"}\n    )\n    staged = tmp_path / "approval-stage"\n    staged.mkdir()\n    records = approval._copy_tree_bounded(\n        source=root,\n        destination=staged,\n        settings=server.runtime.settings,\n        workspace=server.runtime.workspace,\n    )\n    assert records\n\n\ndef test_session_info_names_actual_read_and_commit_boundaries(\n    tmp_path: Path, monkeypatch: pytest.MonkeyPatch\n) -> None:\n    server, _root = _load_server(tmp_path, monkeypatch)\n    properties = server.session_info()["capabilities"]["status"]["broker"]["properties"]\n    assert "filesystem_identity_lock_replace" not in properties\n    assert "same_handle_workspace_read" in properties\n    assert "transactional_workspace_commit" in properties\n    if os.name == "nt":\n        assert properties["same_handle_workspace_read"]["status"] == "verified"\n        assert properties["transactional_workspace_commit"]["status"] == "verified"\n    else:\n        assert properties["same_handle_workspace_read"]["status"] == "unsupported"\n        assert properties["transactional_workspace_commit"]["status"] == "unsupported"\n        assert properties["same_handle_workspace_read"]["production_supported"] is False\n        assert properties["transactional_workspace_commit"]["production_supported"] is False\n''',
    encoding="utf-8",
)

print("same-HANDLE workspace read patch applied")
