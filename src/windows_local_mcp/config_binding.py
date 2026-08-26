from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path
from typing import Any

from .tool_safety import capture_file_identity, hold_file_identity

CONFIG_BINDING_VERSION = 2
_FILE_CONFIG_SOURCE = "LOCAL_MCP_CONFIG"
_CONFIG_SOURCES = {_FILE_CONFIG_SOURCE, "environment_only", "direct_settings"}


def _is_inside(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def _validate_identity_shape(identity: object) -> dict[str, Any]:
    if not isinstance(identity, dict):
        raise TypeError("active config binding has no immutable file identity")
    required = {"path", "sha256", "size", "stable_file_identity", "mtime_ns", "provenance"}
    if not required.issubset(identity):
        raise RuntimeError("active config file identity is incomplete")
    if identity.get("provenance") != "active-config":
        raise RuntimeError("active config file identity has unexpected provenance")
    return deepcopy(identity)


def _verify_bound_file(path: Path, identity: dict[str, Any]) -> dict[str, Any]:
    if str(identity.get("path", "")) != str(path):
        raise RuntimeError("active config path does not match its immutable file identity")
    with hold_file_identity(identity) as held_path:
        if held_path != path:
            raise RuntimeError("active config hold resolved to a different file")
    return deepcopy(identity)


def _bound_selector_path(settings: Any, config_path: Path) -> Path:
    selector_value = getattr(settings, "_config_selector_path", None)
    if selector_value is None:
        selector_value = os.environ.get("LOCAL_MCP_CONFIG", "").strip() or str(config_path)
    selector = Path(str(selector_value)).expanduser().absolute()
    try:
        selected = selector.resolve(strict=True)
    except OSError as error:
        raise RuntimeError("active config selector can no longer be resolved") from error
    if selected != config_path:
        raise RuntimeError("active config selector no longer resolves to the bound config file")
    settings._config_selector_path = str(selector)
    return selector


def export_config_binding(settings: Any) -> dict[str, object]:
    """Return and verify the configuration provenance bound to this Settings instance."""

    config_source = str(getattr(settings, "_config_selection_source", "direct_settings"))
    if config_source not in _CONFIG_SOURCES:
        raise RuntimeError(f"unsupported config selection source: {config_source}")
    workspace_source = str(getattr(settings, "_workspace_selection_source", "settings"))
    ambient_root_present = bool(getattr(settings, "_ambient_root_present", False))
    path_value = getattr(settings, "_config_path", None)
    expected_identity = getattr(settings, "_config_file_identity", None)
    selector_value = getattr(settings, "_config_selector_path", None)

    if path_value is None:
        if config_source == _FILE_CONFIG_SOURCE:
            raise RuntimeError("LOCAL_MCP_CONFIG selection lost its active config path")
        if expected_identity is not None or selector_value is not None:
            raise RuntimeError("configuration identity exists without an active config path")
        return {
            "version": CONFIG_BINDING_VERSION,
            "config_source": config_source,
            "config_selector_path": None,
            "config_path": None,
            "config_file_identity": None,
            "workspace_source": workspace_source,
            "ambient_root_present": ambient_root_present,
        }

    if config_source != _FILE_CONFIG_SOURCE:
        raise RuntimeError("an active config path must originate from LOCAL_MCP_CONFIG")
    path = Path(str(path_value)).resolve(strict=True)
    selector = _bound_selector_path(settings, path)
    workspace = Path(settings.workspace_root).resolve(strict=True)
    if _is_inside(path, workspace):
        raise RuntimeError("the active config path moved inside workspace_root")

    if expected_identity is None:
        identity = capture_file_identity(path, provenance="active-config")
    else:
        identity = _validate_identity_shape(expected_identity)
    identity = _verify_bound_file(path, identity)
    settings._config_file_identity = deepcopy(identity)
    settings._config_path = str(path)

    return {
        "version": CONFIG_BINDING_VERSION,
        "config_source": config_source,
        "config_selector_path": str(selector),
        "config_path": str(path),
        "config_file_identity": deepcopy(identity),
        "workspace_source": workspace_source,
        "ambient_root_present": ambient_root_present,
    }


def restore_config_binding(settings: Any, binding: object) -> None:
    """Restore worker-only PrivateAttr state from a digest-bound worker context."""

    if not isinstance(binding, dict) or binding.get("version") != CONFIG_BINDING_VERSION:
        raise RuntimeError("immutable worker context has no supported config binding")
    config_source = str(binding.get("config_source", ""))
    if config_source not in _CONFIG_SOURCES:
        raise RuntimeError("immutable worker context has an invalid config selection source")
    workspace_source = str(binding.get("workspace_source", ""))
    if not workspace_source:
        raise RuntimeError("immutable worker context has no workspace selection source")
    ambient_root_present = binding.get("ambient_root_present")
    if not isinstance(ambient_root_present, bool):
        raise TypeError("immutable worker context has an invalid ambient-root binding")

    selector_value = binding.get("config_selector_path")
    path_value = binding.get("config_path")
    identity_value = binding.get("config_file_identity")
    if path_value is None:
        if (
            config_source == _FILE_CONFIG_SOURCE
            or selector_value is not None
            or identity_value is not None
        ):
            raise RuntimeError("immutable worker context has an inconsistent config binding")
        settings._config_selection_source = config_source
        settings._config_selector_path = None
        settings._config_path = None
        settings._config_file_identity = None
        settings._workspace_selection_source = workspace_source
        settings._ambient_root_present = ambient_root_present
        return

    if config_source != _FILE_CONFIG_SOURCE or selector_value is None:
        raise RuntimeError("immutable worker context has a file path for a non-file config source")
    path = Path(str(path_value)).resolve(strict=True)
    selector = Path(str(selector_value)).expanduser().absolute()
    try:
        selected = selector.resolve(strict=True)
    except OSError as error:
        raise RuntimeError("immutable worker context config selector cannot be resolved") from error
    if selected != path:
        raise RuntimeError("immutable worker context config selector was retargeted")
    workspace = Path(settings.workspace_root).resolve(strict=True)
    if _is_inside(path, workspace):
        raise RuntimeError("immutable worker context moved the active config inside workspace_root")
    identity = _validate_identity_shape(identity_value)
    identity = _verify_bound_file(path, identity)

    settings._config_selection_source = config_source
    settings._config_selector_path = str(selector)
    settings._config_path = str(path)
    settings._config_file_identity = deepcopy(identity)
    settings._workspace_selection_source = workspace_source
    settings._ambient_root_present = ambient_root_present
