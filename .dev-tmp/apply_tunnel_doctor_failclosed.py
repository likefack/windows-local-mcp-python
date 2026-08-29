from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8-sig")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one match, got {count}: {old[:120]!r}")
    target.write_text(
        text.replace(old, new),
        encoding="utf-8-sig" if path.endswith(".ps1") else "utf-8",
    )


helper = "secure-mcp-tunnel.ps1"
tests = "tests/test_tunnel_setup_diagnostics.py"

replace_once(
    helper,
    '''    $failed = @()
    if ($null -ne $Report) { $failed = @($Report.FailedChecks) }
    if ($failed -contains "tunnel_id") { return "tunnel_id_invalid" }
''',
    '''    if ($null -eq $Report) { return "doctor_output_invalid" }
    $failed = @($Report.FailedChecks)
    if ($failed -contains "tunnel_id") { return "tunnel_id_invalid" }
''',
)

replace_once(
    helper,
    '''    if (@($failed | Where-Object { $_ -in @("profile_load", "config_source", "config_validation", "control_plane_base_url", "control_plane_url_path") }).Count -gt 0) {
        return "profile_invalid"
    }
    return Get-TunnelFailureClass -Stdout $Stdout -Stderr $Stderr -ExitCode $ExitCode
''',
    '''    if (@($failed | Where-Object { $_ -in @("profile_load", "config_source", "config_validation", "control_plane_base_url", "control_plane_url_path") }).Count -gt 0) {
        return "profile_invalid"
    }
    if ([string]$Report.Result -ne "ok") { return "doctor_validation_failed" }
    return Get-TunnelFailureClass -Stdout $Stdout -Stderr $Stderr -ExitCode $ExitCode
''',
)

replace_once(
    helper,
    '''            Succeeded = ($exitCode -eq 0 -and ($null -eq $report -or $report.Result -eq "ok"))
''',
    '''            Succeeded = ($exitCode -eq 0 -and $null -ne $report -and $report.Result -eq "ok")
''',
)

replace_once(
    helper,
    '''        "credential_configuration" {
            Write-Host "Runtime API Key の参照または設定を tunnel-client doctor が確認できません。上の診断詳細を確認し、必要なら key を再入力してください。" -ForegroundColor Yellow
        }
        "profile_invalid" {
''',
    '''        "credential_configuration" {
            Write-Host "Runtime API Key の参照または設定を tunnel-client doctor が確認できません。上の診断詳細を確認し、必要なら key を再入力してください。" -ForegroundColor Yellow
        }
        "doctor_output_invalid" {
            Write-Host "tunnel-client doctor の構造化診断を解析できませんでした。公式 tunnel-client v0.0.10 互換の配布物か確認し、必要なら client を入れ直してください。" -ForegroundColor Yellow
        }
        "doctor_validation_failed" {
            Write-Host "tunnel-client doctor は失敗を返しましたが、失敗項目を特定できませんでした。上の診断内容を確認し、必要なら client または profile を再確認してください。" -ForegroundColor Yellow
        }
        "profile_invalid" {
''',
)

anchor = '''    assert "sk-test-secret" not in output


@pytest.mark.skipif(os.name != "nt", reason="Windows tunnel-client candidate discovery")
'''
insert = '''    assert "sk-test-secret" not in output


@pytest.mark.skipif(os.name != "nt", reason="Windows tunnel-client doctor fail-closed regression")
def test_doctor_invalid_json_is_never_classified_as_success() -> None:
    command = f"""
+$ErrorActionPreference = 'Stop'
+. {_ps_literal(HELPER)}
+$class = Get-TunnelDoctorFailureClass -Report $null -Stdout 'not-json' -Stderr '' -ExitCode 0
+if ($class -ne 'doctor_output_invalid') {{ throw 'invalid doctor JSON did not fail closed: ' + $class }}
+'doctor-invalid-json-failclosed-ok'
+"""
    completed = _run(command)
    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    assert "doctor-invalid-json-failclosed-ok" in output
    helper = HELPER.read_text(encoding="utf-8-sig")
    assert 'Succeeded = ($exitCode -eq 0 -and $null -ne $report -and $report.Result -eq "ok")' in helper


@pytest.mark.skipif(os.name != "nt", reason="Windows tunnel-client candidate discovery")
'''
replace_once(tests, anchor, insert)
