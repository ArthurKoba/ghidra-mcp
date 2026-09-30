"""Persistent project-session lifecycle settings for the bridge router."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from threading import RLock
from typing import Any

_LOCK = RLock()


def _default_idle_timeout_seconds() -> float:
    raw = os.getenv("GHIDRA_MCP_PROJECT_IDLE_TIMEOUT_SECONDS", "900").strip()
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 900.0


def _settings_path() -> Path:
    raw = os.getenv(
        "GHIDRA_MCP_SESSION_SETTINGS_PATH",
        "/data/bridge/project_session_settings.json",
    ).strip()
    return Path(raw)


def _load_persisted() -> dict[str, Any]:
    path = _settings_path()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def idle_timeout_seconds() -> float:
    with _LOCK:
        value = _load_persisted().get("idle_timeout_seconds")
        if isinstance(value, (int, float)):
            return max(0.0, float(value))
        return _default_idle_timeout_seconds()


def get_settings() -> dict[str, Any]:
    timeout = idle_timeout_seconds()
    return {
        "idle_timeout_seconds": timeout,
        "auto_release_enabled": timeout > 0,
        "settings_path": str(_settings_path()),
        "source": "persistent" if _load_persisted() else "environment_default",
    }


def set_idle_timeout_seconds(value: float) -> dict[str, Any]:
    timeout = float(value)
    if not 0 <= timeout <= 86_400:
        raise ValueError("idle_timeout_seconds must be between 0 and 86400")

    with _LOCK:
        path = _settings_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"idle_timeout_seconds": timeout}
        fd, temp_name = tempfile.mkstemp(
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise
    return get_settings()
