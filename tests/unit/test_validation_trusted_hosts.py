from bridge_mcp_ghidra.validation import validate_server_url


def test_loopback_hosts_are_allowed(monkeypatch):
    monkeypatch.delenv("GHIDRA_MCP_TRUSTED_HOSTS", raising=False)
    assert validate_server_url("http://127.0.0.1:8089/")
    assert validate_server_url("http://localhost:8089/")
    assert validate_server_url("http://[::1]:8089/")


def test_non_loopback_host_is_rejected_by_default(monkeypatch):
    monkeypatch.delenv("GHIDRA_MCP_TRUSTED_HOSTS", raising=False)
    assert not validate_server_url("http://ghidra:8089/")


def test_explicit_trusted_host_is_allowed(monkeypatch):
    monkeypatch.setenv("GHIDRA_MCP_TRUSTED_HOSTS", "ghidra, other-internal")
    assert validate_server_url("http://ghidra:8089/")
    assert validate_server_url("http://other-internal:9000/")
    assert not validate_server_url("http://untrusted:8089/")


def test_trusted_host_still_requires_http_and_explicit_port(monkeypatch):
    monkeypatch.setenv("GHIDRA_MCP_TRUSTED_HOSTS", "ghidra")
    assert not validate_server_url("https://ghidra:8089/")
    assert not validate_server_url("http://ghidra/")
