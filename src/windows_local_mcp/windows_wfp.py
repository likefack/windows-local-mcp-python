from __future__ import annotations

import ctypes
import uuid
from ctypes import wintypes

from .wfp_guard import (
    ALE_AUTH_CONNECT_V4,
    ALE_AUTH_CONNECT_V6,
    GUARD_FILTER_NAMES,
    GUARD_SUBLAYER_DESCRIPTION,
    GUARD_SUBLAYER_KEY,
    GUARD_SUBLAYER_NAME,
    GUARD_SUBLAYER_WEIGHT,
    GUARD_V4_FILTER_KEY,
    GUARD_V6_FILTER_KEY,
    FilterConditionSnapshot,
    FilterSnapshot,
    SandboxAccountIdentity,
    SubLayerSnapshot,
    WfpGuardError,
    WfpGuardStateMismatchError,
)

_ERROR_SUCCESS = 0
_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_MORE_DATA = 234
_RPC_C_AUTHN_WINNT = 10
_FWP_E_FILTER_NOT_FOUND = 0x80320003
_FWP_E_SUBLAYER_NOT_FOUND = 0x80320007
_FWP_EMPTY = 0
_FWP_UINT32 = 3
_FWP_UINT64 = 4
_FWP_SECURITY_DESCRIPTOR_TYPE = 14
_FWP_MATCH_EQUAL = 0
_FWP_MATCH_FLAGS_ALL_SET = 6
_FWP_ACTION_BLOCK = 0x00001001
_FWP_CONDITION_FLAG_IS_LOOPBACK = 0x00000001
_SDDL_REVISION_1 = 1
_DACL_SECURITY_INFORMATION = 0x00000004
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_SID_TYPE_USER = 1
_COMPUTER_NAME_PHYSICAL_NETBIOS = 4

_CONDITION_FLAGS = uuid.UUID("632ce23b-5167-435c-86d7-e903684aa80c")
_CONDITION_ALE_USER_ID = uuid.UUID("af043a0a-b34d-4f86-979c-c90371af6e66")


class _Guid(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_uuid(cls, value: uuid.UUID) -> _Guid:
        return cls.from_buffer_copy(value.bytes_le)

    def to_uuid(self) -> uuid.UUID:
        return uuid.UUID(bytes_le=bytes(self))


class _DisplayData(ctypes.Structure):
    _fields_ = [("name", ctypes.c_void_p), ("description", ctypes.c_void_p)]


class _ByteBlob(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.c_void_p)]


class _SubLayer(ctypes.Structure):
    _fields_ = [
        ("subLayerKey", _Guid),
        ("displayData", _DisplayData),
        ("flags", ctypes.c_uint32),
        ("providerKey", ctypes.POINTER(_Guid)),
        ("providerData", _ByteBlob),
        ("weight", ctypes.c_uint16),
    ]


class _FwpValue(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("_padding", ctypes.c_uint32),
        ("value", ctypes.c_uint64),
    ]


class _FilterCondition(ctypes.Structure):
    _fields_ = [
        ("fieldKey", _Guid),
        ("matchType", ctypes.c_uint32),
        ("conditionValue", _FwpValue),
    ]


class _Action(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32), ("filterTypeOrCalloutKey", _Guid)]


class _Context(ctypes.Structure):
    _fields_ = [("data", ctypes.c_ubyte * 16)]


class _Filter(ctypes.Structure):
    _fields_ = [
        ("filterKey", _Guid),
        ("displayData", _DisplayData),
        ("flags", ctypes.c_uint32),
        ("providerKey", ctypes.POINTER(_Guid)),
        ("providerData", _ByteBlob),
        ("layerKey", _Guid),
        ("subLayerKey", _Guid),
        ("weight", _FwpValue),
        ("numFilterConditions", ctypes.c_uint32),
        ("filterCondition", ctypes.POINTER(_FilterCondition)),
        ("action", _Action),
        ("context", _Context),
        ("reserved", ctypes.c_void_p),
        ("filterId", ctypes.c_uint64),
        ("effectiveWeight", _FwpValue),
    ]


class _Session(ctypes.Structure):
    _fields_ = [
        ("sessionKey", _Guid),
        ("displayData", _DisplayData),
        ("flags", ctypes.c_uint32),
        ("txnWaitTimeoutInMSec", ctypes.c_uint32),
        ("processId", ctypes.c_uint32),
        ("sid", ctypes.c_void_p),
        ("username", ctypes.c_void_p),
        ("kernelMode", wintypes.BOOL),
    ]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", ctypes.c_uint32)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("User", _SidAndAttributes)]


class WindowsWfpApi:
    """Narrow fwpuclnt wrapper for the fixed Codex loopback policy only."""

    def __init__(self) -> None:
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            raise WfpGuardError("The WFP Guard requires a 64-bit process")
        self._fwpuclnt = ctypes.WinDLL("fwpuclnt.dll", use_last_error=True)
        self._advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        self._configure_functions()

    def resolve_account_identity(self, account_name: str) -> SandboxAccountIdentity:
        if not account_name or "\\" in account_name:
            raise WfpGuardError("The WFP Guard target must be an unqualified local account name")
        local_computer_name = self._local_computer_name()
        # 単純名の解決は信頼ドメインへ広がり得るため、このPCの名前で対象を限定する。
        qualified_account_name = f"{local_computer_name}\\{account_name}"
        sid_size = wintypes.DWORD(0)
        domain_size = wintypes.DWORD(0)
        use = wintypes.DWORD(0)
        self._advapi32.LookupAccountNameW(
            None,
            qualified_account_name,
            None,
            ctypes.byref(sid_size),
            None,
            ctypes.byref(domain_size),
            ctypes.byref(use),
        )
        if (
            ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER or sid_size.value == 0
        ):  # ERROR_INSUFFICIENT_BUFFER
            self._raise_last_error("LookupAccountNameW(size)")
        sid = ctypes.create_string_buffer(sid_size.value)
        domain = ctypes.create_unicode_buffer(domain_size.value)
        if not self._advapi32.LookupAccountNameW(
            None,
            qualified_account_name,
            sid,
            ctypes.byref(sid_size),
            domain,
            ctypes.byref(domain_size),
            ctypes.byref(use),
        ):
            self._raise_last_error("LookupAccountNameW")
        self._verify_local_user_resolution(
            account_name=account_name,
            resolved_domain=domain.value,
            local_computer_name=local_computer_name,
            sid_name_use=use.value,
        )
        resolved = self._sid_to_string(ctypes.cast(sid, ctypes.c_void_p))
        if resolved == self._current_process_sid():
            raise WfpGuardStateMismatchError(
                "CodexSandboxOffline SID equals the Guard operator SID"
            )
        return SandboxAccountIdentity(
            account_name=account_name,
            computer_name=local_computer_name,
            qualified_account_name=qualified_account_name,
            sid=resolved,
            sid_name_use=int(use.value),
        )

    def read_sublayer(self, key: uuid.UUID) -> SubLayerSnapshot:
        with self._engine() as engine:
            return self._read_sublayer(engine, key)

    def read_filter(self, key: uuid.UUID) -> FilterSnapshot:
        with self._engine() as engine:
            return self._read_filter(engine, key)

    def add_sublayer(self) -> None:
        with self._engine(static_session=True) as engine:
            name = ctypes.create_unicode_buffer(GUARD_SUBLAYER_NAME)
            description = ctypes.create_unicode_buffer(GUARD_SUBLAYER_DESCRIPTION)
            item = _SubLayer()
            item.subLayerKey = _Guid.from_uuid(GUARD_SUBLAYER_KEY)
            item.displayData.name = ctypes.cast(name, ctypes.c_void_p).value
            item.displayData.description = ctypes.cast(description, ctypes.c_void_p).value
            item.flags = 0
            item.providerKey = None
            item.providerData = _ByteBlob(0, None)
            item.weight = GUARD_SUBLAYER_WEIGHT
            self._transaction_begin(engine)
            committed = False
            try:
                self._check(
                    self._fwpuclnt.FwpmSubLayerAdd0(engine, ctypes.byref(item), None),
                    "FwpmSubLayerAdd0",
                )
                self._check(
                    self._fwpuclnt.FwpmTransactionCommit0(engine),
                    "FwpmTransactionCommit0(sublayer)",
                )
                committed = True
            finally:
                if not committed:
                    self._fwpuclnt.FwpmTransactionAbort0(engine)

    def add_filters(self, *, add_v4: bool, add_v6: bool, target_sid: str) -> None:
        if not add_v4 and not add_v6:
            return
        security_descriptor = ctypes.c_void_p()
        descriptor_size = wintypes.DWORD(0)
        sddl = f"D:(A;;0x1;;;{target_sid})"
        if not self._advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            _SDDL_REVISION_1,
            ctypes.byref(security_descriptor),
            ctypes.byref(descriptor_size),
        ):
            self._raise_last_error("ConvertStringSecurityDescriptorToSecurityDescriptorW")
        try:
            length = self._advapi32.GetSecurityDescriptorLength(security_descriptor)
            if not length:
                self._raise_last_error("GetSecurityDescriptorLength")
            blob = _ByteBlob(length, security_descriptor.value)
            conditions = (_FilterCondition * 2)()
            conditions[0].fieldKey = _Guid.from_uuid(_CONDITION_ALE_USER_ID)
            conditions[0].matchType = _FWP_MATCH_EQUAL
            conditions[0].conditionValue.type = _FWP_SECURITY_DESCRIPTOR_TYPE
            conditions[0].conditionValue.value = ctypes.addressof(blob)
            conditions[1].fieldKey = _Guid.from_uuid(_CONDITION_FLAGS)
            conditions[1].matchType = _FWP_MATCH_FLAGS_ALL_SET
            conditions[1].conditionValue.type = _FWP_UINT32
            conditions[1].conditionValue.value = _FWP_CONDITION_FLAG_IS_LOOPBACK
            keepalive: list[object] = [blob, conditions]
            filters: list[_Filter] = []
            if add_v4:
                filters.append(
                    self._build_filter(
                        GUARD_V4_FILTER_KEY,
                        ALE_AUTH_CONNECT_V4,
                        GUARD_FILTER_NAMES["v4"],
                        conditions,
                        keepalive,
                    )
                )
            if add_v6:
                filters.append(
                    self._build_filter(
                        GUARD_V6_FILTER_KEY,
                        ALE_AUTH_CONNECT_V6,
                        GUARD_FILTER_NAMES["v6"],
                        conditions,
                        keepalive,
                    )
                )
            with self._engine(static_session=True) as engine:
                self._transaction_begin(engine)
                committed = False
                try:
                    for item in filters:
                        runtime_id = ctypes.c_uint64()
                        self._check(
                            self._fwpuclnt.FwpmFilterAdd0(
                                engine, ctypes.byref(item), None, ctypes.byref(runtime_id)
                            ),
                            "FwpmFilterAdd0",
                        )
                    self._check(
                        self._fwpuclnt.FwpmTransactionCommit0(engine),
                        "FwpmTransactionCommit0(filters)",
                    )
                    committed = True
                finally:
                    if not committed:
                        self._fwpuclnt.FwpmTransactionAbort0(engine)
        finally:
            self._kernel32.LocalFree(security_descriptor)

    def delete_filter(self, key: uuid.UUID) -> None:
        with self._engine(static_session=True) as engine:
            native = _Guid.from_uuid(key)
            self._check(
                self._fwpuclnt.FwpmFilterDeleteByKey0(engine, ctypes.byref(native)),
                "FwpmFilterDeleteByKey0",
            )

    def delete_sublayer(self, key: uuid.UUID) -> None:
        with self._engine(static_session=True) as engine:
            native = _Guid.from_uuid(key)
            self._check(
                self._fwpuclnt.FwpmSubLayerDeleteByKey0(engine, ctypes.byref(native)),
                "FwpmSubLayerDeleteByKey0",
            )

    def _read_sublayer(self, engine: ctypes.c_void_p, key: uuid.UUID) -> SubLayerSnapshot:
        pointer = ctypes.c_void_p()
        native = _Guid.from_uuid(key)
        result = self._fwpuclnt.FwpmSubLayerGetByKey0(
            engine, ctypes.byref(native), ctypes.byref(pointer)
        )
        if result == _FWP_E_SUBLAYER_NOT_FOUND:
            return SubLayerSnapshot(found=False, key=key)
        self._check(result, "FwpmSubLayerGetByKey0")
        try:
            item = ctypes.cast(pointer, ctypes.POINTER(_SubLayer)).contents
            return SubLayerSnapshot(
                found=True,
                key=item.subLayerKey.to_uuid(),
                name=self._wstring(item.displayData.name),
                description=self._wstring(item.displayData.description),
                flags=item.flags,
                provider_key=item.providerKey.contents.to_uuid() if item.providerKey else None,
                provider_data_size=item.providerData.size,
                weight=item.weight,
            )
        finally:
            self._free_wfp_memory(pointer)

    def _read_filter(self, engine: ctypes.c_void_p, key: uuid.UUID) -> FilterSnapshot:
        pointer = ctypes.c_void_p()
        native = _Guid.from_uuid(key)
        result = self._fwpuclnt.FwpmFilterGetByKey0(
            engine, ctypes.byref(native), ctypes.byref(pointer)
        )
        if result == _FWP_E_FILTER_NOT_FOUND:
            return FilterSnapshot(found=False, key=key)
        self._check(result, "FwpmFilterGetByKey0")
        try:
            item = ctypes.cast(pointer, ctypes.POINTER(_Filter)).contents
            conditions = tuple(
                self._condition_snapshot(item.filterCondition[index])
                for index in range(item.numFilterConditions)
            )
            return FilterSnapshot(
                found=True,
                key=item.filterKey.to_uuid(),
                runtime_id=item.filterId,
                name=self._wstring(item.displayData.name),
                description=self._wstring(item.displayData.description),
                flags=item.flags,
                provider_key=item.providerKey.contents.to_uuid() if item.providerKey else None,
                provider_data_size=item.providerData.size,
                layer_key=item.layerKey.to_uuid(),
                sublayer_key=item.subLayerKey.to_uuid(),
                action="block" if item.action.type == _FWP_ACTION_BLOCK else hex(item.action.type),
                weight_type="empty" if item.weight.type == _FWP_EMPTY else str(item.weight.type),
                effective_weight=self._numeric_weight(item.effectiveWeight),
                conditions=conditions,
            )
        finally:
            self._free_wfp_memory(pointer)

    def _condition_snapshot(self, condition: _FilterCondition) -> FilterConditionSnapshot:
        field = condition.fieldKey.to_uuid()
        if field == _CONDITION_ALE_USER_ID:
            if (
                condition.matchType != _FWP_MATCH_EQUAL
                or condition.conditionValue.type != _FWP_SECURITY_DESCRIPTOR_TYPE
                or not condition.conditionValue.value
            ):
                return FilterConditionSnapshot("ale_user_id", "invalid", "invalid")
            blob = ctypes.cast(condition.conditionValue.value, ctypes.POINTER(_ByteBlob)).contents
            sid, normalized_sddl = self._security_descriptor_identity(blob.data)
            return FilterConditionSnapshot(
                kind="ale_user_id",
                match_type="equal",
                value_type="security_descriptor",
                sid=sid,
                security_descriptor_sddl=normalized_sddl,
            )
        if field == _CONDITION_FLAGS:
            return FilterConditionSnapshot(
                kind="flags",
                match_type=(
                    "flags_all_set"
                    if condition.matchType == _FWP_MATCH_FLAGS_ALL_SET
                    else "invalid"
                ),
                value_type="uint32" if condition.conditionValue.type == _FWP_UINT32 else "invalid",
                flags=condition.conditionValue.value & 0xFFFFFFFF,
            )
        return FilterConditionSnapshot(str(field), "unknown", str(condition.conditionValue.type))

    def _security_descriptor_identity(self, descriptor: int | None) -> tuple[str, str]:
        if not descriptor:
            raise WfpGuardError("WFP ALE user condition has no security descriptor")
        owner = wintypes.BOOL()
        dacl_present = wintypes.BOOL()
        dacl_defaulted = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        if not self._advapi32.GetSecurityDescriptorDacl(
            descriptor,
            ctypes.byref(dacl_present),
            ctypes.byref(dacl),
            ctypes.byref(dacl_defaulted),
        ):
            self._raise_last_error("GetSecurityDescriptorDacl")
        del owner, dacl_defaulted
        if not dacl_present.value or not dacl.value:
            raise WfpGuardError("WFP ALE user condition has no DACL")
        ace = ctypes.c_void_p()
        if not self._advapi32.GetAce(dacl, 0, ctypes.byref(ace)):
            self._raise_last_error("GetAce")
        # ACCESS_ALLOWED_ACE starts with ACE_HEADER (4 bytes), mask (4 bytes), then SID.
        sid = self._sid_to_string(ctypes.c_void_p(ace.value + 8))
        output = ctypes.c_void_p()
        output_length = wintypes.ULONG()
        if not self._advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            _SDDL_REVISION_1,
            _DACL_SECURITY_INFORMATION,
            ctypes.byref(output),
            ctypes.byref(output_length),
        ):
            self._raise_last_error("ConvertSecurityDescriptorToStringSecurityDescriptorW")
        try:
            normalized_sddl = ctypes.wstring_at(output)
        finally:
            self._kernel32.LocalFree(output)
        return sid, normalized_sddl

    def _build_filter(
        self,
        key: uuid.UUID,
        layer: uuid.UUID,
        name_text: str,
        conditions: ctypes.Array[_FilterCondition],
        keepalive: list[object],
    ) -> _Filter:
        name = ctypes.create_unicode_buffer(name_text)
        description = ctypes.create_unicode_buffer(
            "Blocks CodexSandboxOffline loopback at ALE_AUTH_CONNECT."
        )
        keepalive.extend((name, description))
        item = _Filter()
        item.filterKey = _Guid.from_uuid(key)
        item.displayData.name = ctypes.cast(name, ctypes.c_void_p).value
        item.displayData.description = ctypes.cast(description, ctypes.c_void_p).value
        item.flags = 0
        item.providerKey = None
        item.providerData = _ByteBlob(0, None)
        item.layerKey = _Guid.from_uuid(layer)
        item.subLayerKey = _Guid.from_uuid(GUARD_SUBLAYER_KEY)
        item.weight.type = _FWP_EMPTY
        item.weight.value = 0
        item.numFilterConditions = 2
        item.filterCondition = ctypes.cast(conditions, ctypes.POINTER(_FilterCondition))
        item.action.type = _FWP_ACTION_BLOCK
        return item

    def _numeric_weight(self, value: _FwpValue) -> int | None:
        if value.type == _FWP_UINT64 and value.value:
            return ctypes.cast(value.value, ctypes.POINTER(ctypes.c_uint64)).contents.value
        if value.type == _FWP_UINT32:
            return value.value & 0xFFFFFFFF
        return None

    def _local_computer_name(self) -> str:
        size = wintypes.DWORD(0)
        if self._kernel32.GetComputerNameExW(
            _COMPUTER_NAME_PHYSICAL_NETBIOS,
            None,
            ctypes.byref(size),
        ):
            raise WfpGuardError("GetComputerNameExW returned an unexpected success")
        if (
            ctypes.get_last_error() not in (_ERROR_MORE_DATA, _ERROR_INSUFFICIENT_BUFFER)
            or not size.value
        ):
            self._raise_last_error("GetComputerNameExW(size)")
        buffer = ctypes.create_unicode_buffer(size.value)
        if not self._kernel32.GetComputerNameExW(
            _COMPUTER_NAME_PHYSICAL_NETBIOS,
            buffer,
            ctypes.byref(size),
        ):
            self._raise_last_error("GetComputerNameExW")
        if not buffer.value:
            raise WfpGuardError("GetComputerNameExW returned an empty computer name")
        return buffer.value

    @staticmethod
    def _verify_local_user_resolution(
        *,
        account_name: str,
        resolved_domain: str,
        local_computer_name: str,
        sid_name_use: int,
    ) -> None:
        if (
            not resolved_domain
            or not local_computer_name
            or resolved_domain.casefold() != local_computer_name.casefold()
        ):
            raise WfpGuardStateMismatchError(
                f"LookupAccountNameW resolved {account_name} outside this computer"
            )
        if sid_name_use != _SID_TYPE_USER:
            raise WfpGuardStateMismatchError(
                f"LookupAccountNameW resolved {account_name} as SID_NAME_USE={sid_name_use}, "
                "not SidTypeUser"
            )

    def _current_process_sid(self) -> str:
        token = wintypes.HANDLE()
        if not self._advapi32.OpenProcessToken(
            self._kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
        ):
            self._raise_last_error("OpenProcessToken")
        try:
            size = wintypes.DWORD(0)
            self._advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(size))
            if ctypes.get_last_error() != 122 or not size.value:
                self._raise_last_error("GetTokenInformation(size)")
            buffer = ctypes.create_string_buffer(size.value)
            if not self._advapi32.GetTokenInformation(
                token, _TOKEN_USER, buffer, size, ctypes.byref(size)
            ):
                self._raise_last_error("GetTokenInformation")
            user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
            return self._sid_to_string(user.User.Sid)
        finally:
            self._kernel32.CloseHandle(token)

    def _sid_to_string(self, sid: ctypes.c_void_p) -> str:
        output = ctypes.c_void_p()
        if not self._advapi32.ConvertSidToStringSidW(sid, ctypes.byref(output)):
            self._raise_last_error("ConvertSidToStringSidW")
        try:
            return ctypes.wstring_at(output)
        finally:
            self._kernel32.LocalFree(output)

    def _engine(self, *, static_session: bool = False) -> _EngineContext:
        return _EngineContext(self, static_session=static_session)

    def _transaction_begin(self, engine: ctypes.c_void_p) -> None:
        self._check(self._fwpuclnt.FwpmTransactionBegin0(engine, 0), "FwpmTransactionBegin0")

    def _free_wfp_memory(self, pointer: ctypes.c_void_p) -> None:
        self._fwpuclnt.FwpmFreeMemory0(ctypes.byref(pointer))

    @staticmethod
    def _wstring(pointer: int | None) -> str:
        return ctypes.wstring_at(pointer) if pointer else ""

    @staticmethod
    def _check(result: int, operation: str) -> None:
        if result != _ERROR_SUCCESS:
            raise WfpGuardError(f"{operation} failed with WFP status 0x{result:08X}")

    @staticmethod
    def _raise_last_error(operation: str) -> None:
        raise WfpGuardError(f"{operation} failed with WinError {ctypes.get_last_error()}")

    def _configure_functions(self) -> None:
        f = self._fwpuclnt
        f.FwpmEngineOpen0.argtypes = [
            wintypes.LPCWSTR,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(_Session),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        f.FwpmEngineOpen0.restype = ctypes.c_uint32
        f.FwpmEngineClose0.argtypes = [ctypes.c_void_p]
        f.FwpmEngineClose0.restype = ctypes.c_uint32
        f.FwpmTransactionBegin0.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        f.FwpmTransactionBegin0.restype = ctypes.c_uint32
        f.FwpmTransactionCommit0.argtypes = [ctypes.c_void_p]
        f.FwpmTransactionCommit0.restype = ctypes.c_uint32
        f.FwpmTransactionAbort0.argtypes = [ctypes.c_void_p]
        f.FwpmTransactionAbort0.restype = ctypes.c_uint32
        f.FwpmSubLayerAdd0.argtypes = [ctypes.c_void_p, ctypes.POINTER(_SubLayer), ctypes.c_void_p]
        f.FwpmSubLayerAdd0.restype = ctypes.c_uint32
        f.FwpmSubLayerGetByKey0.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_Guid),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        f.FwpmSubLayerGetByKey0.restype = ctypes.c_uint32
        f.FwpmSubLayerDeleteByKey0.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Guid)]
        f.FwpmSubLayerDeleteByKey0.restype = ctypes.c_uint32
        f.FwpmFilterAdd0.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_Filter),
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint64),
        ]
        f.FwpmFilterAdd0.restype = ctypes.c_uint32
        f.FwpmFilterGetByKey0.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_Guid),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        f.FwpmFilterGetByKey0.restype = ctypes.c_uint32
        f.FwpmFilterDeleteByKey0.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Guid)]
        f.FwpmFilterDeleteByKey0.restype = ctypes.c_uint32
        f.FwpmFreeMemory0.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        f.FwpmFreeMemory0.restype = None

        a = self._advapi32
        a.LookupAccountNameW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        a.LookupAccountNameW.restype = wintypes.BOOL
        a.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        a.ConvertSidToStringSidW.restype = wintypes.BOOL
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
        ]
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
        a.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.ULONG),
        ]
        a.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
        a.GetSecurityDescriptorLength.argtypes = [ctypes.c_void_p]
        a.GetSecurityDescriptorLength.restype = wintypes.DWORD
        a.GetSecurityDescriptorDacl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.BOOL),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.BOOL),
        ]
        a.GetSecurityDescriptorDacl.restype = wintypes.BOOL
        a.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
        a.GetAce.restype = wintypes.BOOL
        a.OpenProcessToken.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        a.OpenProcessToken.restype = wintypes.BOOL
        a.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_uint32,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        a.GetTokenInformation.restype = wintypes.BOOL

        k = self._kernel32
        k.GetComputerNameExW.argtypes = [
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        k.GetComputerNameExW.restype = wintypes.BOOL
        k.GetCurrentProcess.argtypes = []
        k.GetCurrentProcess.restype = wintypes.HANDLE
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.CloseHandle.restype = wintypes.BOOL
        k.LocalFree.argtypes = [ctypes.c_void_p]
        k.LocalFree.restype = ctypes.c_void_p


class _EngineContext:
    def __init__(self, api: WindowsWfpApi, *, static_session: bool) -> None:
        self._api = api
        self._static_session = static_session
        self._handle = ctypes.c_void_p()

    def __enter__(self) -> ctypes.c_void_p:
        session = _Session()
        session.sessionKey = _Guid.from_uuid(uuid.uuid4())
        session.flags = 0  # Static, non-dynamic session; objects also omit persistent flags.
        session_pointer = ctypes.byref(session) if self._static_session else None
        self._api._check(
            self._api._fwpuclnt.FwpmEngineOpen0(
                None,
                _RPC_C_AUTHN_WINNT,
                None,
                session_pointer,
                ctypes.byref(self._handle),
            ),
            "FwpmEngineOpen0",
        )
        return self._handle

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self._handle.value:
            result = self._api._fwpuclnt.FwpmEngineClose0(self._handle)
            self._handle = ctypes.c_void_p()
            self._api._check(result, "FwpmEngineClose0")
