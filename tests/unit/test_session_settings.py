from __future__ import annotations

import json

from bridge_mcp_ghidra import session_settings


def test_session_settings_fall_back_to_environment(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "GHIDRA_MCP_SESSION_SETTINGS_PATH",
        str(tmp_path / "settings.json"),
    )
    monkeypatch.setenv("GHIDRA_MCP_PROJECT_IDLE_TIMEOUT_SECONDS", "321")

    settings = session_settings.get_settings()

    assert settings["idle_timeout_seconds"] == 321.0
    assert settings["auto_release_enabled"] is True
    assert settings["source"] == "environment_default"


def test_session_settings_persist_idle_timeout(monkeypatch, tmp_path):
    path = tmp_path / "settings.json"
    monkeypatch.setenv("GHIDRA_MCP_SESSION_SETTINGS_PATH", str(path))

    saved = session_settings.set_idle_timeout_seconds(120)

    assert saved["idle_timeout_seconds"] == 120.0
    assert saved["source"] == "persistent"
    assert json.loads(path.read_text()) == {"idle_timeout_seconds": 120.0}


def test_zero_idle_timeout_disables_auto_release(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "GHIDRA_MCP_SESSION_SETTINGS_PATH",
        str(tmp_path / "settings.json"),
    )

    saved = session_settings.set_idle_timeout_seconds(0)

    assert saved["auto_release_enabled"] is False
    assert session_settings.idle_timeout_seconds() == 0.0
