from pathlib import Path

path = Path(__file__).with_name("apply_approved_host_ci_regressions.py")
text = path.read_text(encoding="utf-8")
old = '''replace_once(\n    "src/windows_local_mcp/control_plane_guard.py",\n    \'\'\'                    "acl_sha256": _startup_path_acl_digest(resolved),\\n\'\'\',\n    \'\'\'                    "acl_sha256": _startup_path_acl_digest(\\n                        resolved, deadline=deadline\\n                    ),\\n\'\'\',\n    "startup file ACL deadline propagation",\n)\nreplace_once(\n    "src/windows_local_mcp/control_plane_guard.py",\n    \'\'\'                    "acl_sha256": _startup_path_acl_digest(resolved),\\n\'\'\',\n    \'\'\'                    "acl_sha256": _startup_path_acl_digest(\\n                        resolved, deadline=deadline\\n                    ),\\n\'\'\',\n    "startup directory ACL deadline propagation",\n)\n'''
new = '''text = read("src/windows_local_mcp/control_plane_guard.py")\nold_acl = \'\'\'                    "acl_sha256": _startup_path_acl_digest(resolved),\\n\'\'\'\nnew_acl = \'\'\'                    "acl_sha256": _startup_path_acl_digest(\\n                        resolved, deadline=deadline\\n                    ),\\n\'\'\'\nif text.count(old_acl) != 2:\n    raise RuntimeError(\n        "src/windows_local_mcp/control_plane_guard.py: startup ACL propagation: "\n        f"expected two replacement targets, found {text.count(old_acl)}"\n    )\nwrite("src/windows_local_mcp/control_plane_guard.py", text.replace(old_acl, new_acl))\n'''
if old not in text:
    raise RuntimeError("harness repair target not found")
path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")
