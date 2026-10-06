"""Verify setup diagnostics without exposing or persisting attachment credentials."""
import json

import pytest
from test_high_level_operations import load_server

from windows_local_mcp.artifact_errors import ArtifactTransferError
from windows_local_mcp.attachment_import import validate_reference


@pytest.mark.parametrize(
    ("allowed_hosts", "error_code"),
    [([], "ATTACHMENT_IMPORT_NOT_CONFIGURED"),
     (["previous-files.example.com"], "ATTACHMENT_REFERENCE_REJECTED")],
)
def test_import_reports_only_actual_dns_host_before_network(
    tmp_path, monkeypatch, allowed_hosts, error_code
):
    server, root = load_server(tmp_path, monkeypatch)
    server.runtime.settings.attachment_import_allowed_hosts = allowed_hosts.copy()
    monkeypatch.setattr(server, "download_attachment", lambda *a, **kw: pytest.fail("network reached"))
    reference = {
        "download_url": "https://actual-files.example.com/private-path?signature=private-token",
        "file_id": "file_private_id",
        "file_name": "private-name.jpg",
    }
    with pytest.raises(ArtifactTransferError, match=error_code) as raised:
        server.artifact_import_file(reference, "not-created.jpg")
    message = str(raised.value)
    assert "actual-files.example.com" in message
    for private in ("private-path", "private-token", "file_private_id", "private-name.jpg"):
        assert private not in message
    assert not (root / "not-created.jpg").exists()
    audit = json.dumps(server.runtime.audit.list_operations(limit=10))
    assert "actual-files.example.com" not in audit
    assert error_code in audit
    for private in ("private-path", "private-token", "file_private_id", "private-name.jpg"):
        assert private not in audit
    if allowed_hosts:
        assert "reason=host_not_permitted" in message
        assert "reason=host_not_permitted" in audit
    assert server.runtime.settings.attachment_import_allowed_hosts == allowed_hosts


@pytest.mark.parametrize("allowed_hosts", [[], ["previous-files.example.com"]])
@pytest.mark.parametrize(
    "host", ["127.0.0.1", "invalid_host.example", "files.example.com.",
             "-files.example.com", "localhost", "a" * 64 + ".example.com"]
)
def test_setup_diagnostic_rejects_non_dns_hosts(host, allowed_hosts):
    with pytest.raises(ArtifactTransferError, match="ATTACHMENT_REFERENCE_REJECTED") as raised:
        validate_reference({"download_url": f"https://{host}/image", "file_id": "f"}, allowed_hosts)
    assert host not in str(raised.value)
    assert "observed file-service host" not in str(raised.value)
    if allowed_hosts:
        assert "reason=host_not_permitted" in str(raised.value)


def test_permitted_host_retains_request_target():
    assert validate_reference(
        {"download_url": "https://actual-files.example.com/image?signature=token", "file_id": "f"},
        ["actual-files.example.com"],
    ) == ("actual-files.example.com", "/image?signature=token")
