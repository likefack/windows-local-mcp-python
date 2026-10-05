import ctypes
import hashlib
import json
import os
from ctypes import wintypes

import pytest

from windows_local_mcp.config import _assert_local_sandbox_group_sid, _canonical_data_acl_records

USER = "S-1-5-21-100-200-300-1001"
GROUP = "S-1-5-21-100-200-300-1003"
SYSTEM = "S-1-5-18"
FULL = 0x1F01FF
SPLIT = [(0, flags, FULL, sid) for sid in (USER, SYSTEM) for flags in (0, 11)]
COMBINED = [(0, 3, FULL, sid) for sid in (USER, SYSTEM)]
DENIALS = [(1, 0, 0x120089, GROUP), (1, 11, 0x80120089, GROUP)]


@pytest.mark.parametrize("allows", [SPLIT, COMBINED, SPLIT[:2] + COMBINED[1:]])
@pytest.mark.parametrize("denials", [[], DENIALS])
def test_equivalent_acl_retains_existing_marker_digest(allows, denials):
    # Existing markers bind the split grant representation; extra read denials
    # must neither grant access nor require rewriting the trusted marker.
    canonical = _canonical_data_acl_records(
        denials + allows, USER, sandbox_group_sid=GROUP if denials else None
    )

    def digest(records):
        return hashlib.sha256(
            json.dumps(
                {"protected": True, "aces": sorted(records)},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

    assert digest(canonical) == digest(SPLIT)


@pytest.mark.parametrize(
    "records",
    [
        COMBINED + [(0, 0, 0x120089, "S-1-1-0")],  # Additional public read grant.
        COMBINED + [COMBINED[0]],
        SPLIT + [COMBINED[0]],
        COMBINED[:1],
        [(0, 3, FULL ^ 2, USER), COMBINED[1]],
        [(0, 0x13, FULL, USER), COMBINED[1]],  # Inherited root grant.
        [(0, 7, FULL, USER), COMBINED[1]],  # No-propagate is not equivalent.
        DENIALS[:1] + COMBINED,
        DENIALS[1:] + COMBINED,
        DENIALS + DENIALS[:1] + COMBINED,
        COMBINED + DENIALS,
        DENIALS[:1] + COMBINED[:1] + DENIALS[1:] + COMBINED[1:],
        [(1, 0, 0x120089, USER), DENIALS[1]] + COMBINED,
        [(1, 0, FULL, GROUP), DENIALS[1]] + COMBINED,
        [DENIALS[0], (1, 3, 0x80120089, GROUP)] + COMBINED,
        [(2, 0, 0x120089, GROUP)] + COMBINED,
    ],
)
def test_unknown_or_changed_acl_is_rejected(records):
    with pytest.raises(PermissionError):
        _canonical_data_acl_records(records, USER, sandbox_group_sid=GROUP)


@pytest.mark.parametrize("group", [None, USER, SYSTEM, "S-1-1-0"])
def test_denials_require_independently_verified_local_group(group):
    with pytest.raises(PermissionError):
        _canonical_data_acl_records(DENIALS + COMBINED, USER, sandbox_group_sid=group)


@pytest.mark.skipif(os.name != "nt", reason="native Windows account resolution")
@pytest.mark.parametrize("sid", ["S-1-1-0", SYSTEM])
def test_native_account_resolution_rejects_other_principals(sid):
    # A well-known group or SYSTEM cannot impersonate the local Sandbox alias.
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = api.ConvertStringSidToSidW
    convert.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    convert.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    pointer = ctypes.c_void_p()
    assert convert(sid, ctypes.byref(pointer))
    try:
        with pytest.raises(PermissionError):
            _assert_local_sandbox_group_sid(pointer)
    finally:
        kernel.LocalFree(pointer)
