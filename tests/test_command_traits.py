from windows_local_mcp.command_traits import SafeExecutionKind, classify_safe_execution
from windows_local_mcp.policy import NormalizedCommand


def command(program_key: str, args: list[str]) -> NormalizedCommand:
    return NormalizedCommand(
        executable=f"C:/tools/{program_key}.exe",
        args=args,
        cwd="C:/workspace",
        display_command=[program_key, *args],
        program_key=program_key,
    )


def test_safe_command_classes_match_tool_surfaces() -> None:
    assert classify_safe_execution(command("git", ["--no-pager", "status", "--short"])) == SafeExecutionKind.READ_ONLY
    assert classify_safe_execution(command("flutter", ["analyze", "--no-pub"])) == SafeExecutionKind.READ_ONLY
    assert classify_safe_execution(command("dart", ["analyze"])) == SafeExecutionKind.READ_ONLY
    assert classify_safe_execution(command("dart", ["format", "--output=show", "C:/workspace/lib"])) == SafeExecutionKind.READ_ONLY
    assert classify_safe_execution(command("dart", ["format", "C:/workspace/lib"])) == SafeExecutionKind.WORKSPACE_WRITE
    assert classify_safe_execution(command("adb", ["devices"])) == SafeExecutionKind.ADB_READ


def test_unknown_or_unvalidated_shapes_fail_closed() -> None:
    for item in (
        command("python", ["script.py"]),
        command("flutter", ["test"]),
        command("dart", ["test"]),
    ):
        try:
            classify_safe_execution(item)
        except PermissionError:
            pass
        else:
            raise AssertionError("unvalidated command shape must not receive a safe tool class")
