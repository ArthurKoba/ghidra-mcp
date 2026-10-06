"""Private raw artifact upload for trusted Analysis service traffic."""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse

from . import project_sessions, state

_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_DEFAULT_MAX_BYTES = 8 * 1024 * 1024 * 1024


def _upload_root() -> Path:
    root = Path(os.getenv("GHIDRA_MCP_FILE_ROOT", "/artifacts")).resolve(strict=False)
    return root / ".koba-direct"


def _max_upload_bytes() -> int:
    raw = os.getenv("GHIDRA_MCP_DIRECT_UPLOAD_MAX_BYTES", str(_DEFAULT_MAX_BYTES))
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_MAX_BYTES
    return max(1, value)


def _safe_name(value: str) -> str:
    name = Path(value.strip()).name
    if not name or not _SAFE_NAME.fullmatch(name):
        raise ValueError("invalid artifact name")
    return name


async def direct_artifact_upload(request: Request) -> JSONResponse:
    """Stream one normal file into Hydra artifact storage without base64.

    Existing MCP artifact_stage_* tools remain the compatibility path for
    clients that can only transport base64 chunks.
    """
    if request.headers.get("x-koba-proxy-origin", "").casefold() != "analysis":
        return JSONResponse(
            {"error": "direct artifact upload is restricted to Analysis"},
            status_code=403,
        )

    project_id = request.query_params.get("project_id", "").strip()
    if not project_id:
        return JSONResponse({"error": "project_id is required"}, status_code=400)

    try:
        name = _safe_name(request.query_params.get("name", ""))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    try:
        await state.run_in_worker(project_sessions.ensure_session, project_id)
    except project_sessions.ProjectSessionError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)

    expected_sha = request.headers.get("x-artifact-sha256", "").strip().lower()
    expected_size_raw = request.headers.get("x-artifact-size", "").strip()
    try:
        expected_size = int(expected_size_raw) if expected_size_raw else None
    except ValueError:
        return JSONResponse({"error": "invalid x-artifact-size"}, status_code=400)

    max_bytes = _max_upload_bytes()
    if expected_size is not None and (expected_size < 0 or expected_size > max_bytes):
        return JSONResponse(
            {"error": "artifact size exceeds configured direct-upload limit"},
            status_code=413,
        )

    root = _upload_root()
    root.mkdir(parents=True, exist_ok=True)
    target = root / f"{uuid.uuid4().hex}-{name}"
    digest = hashlib.sha256()
    size = 0

    try:
        with target.open("xb") as handle:
            async for chunk in request.stream():
                if not chunk:
                    continue
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError("artifact size exceeds configured direct-upload limit")
                handle.write(chunk)
                digest.update(chunk)
            handle.flush()
            os.fsync(handle.fileno())

        actual_sha = digest.hexdigest()
        if expected_size is not None and size != expected_size:
            raise ValueError(f"artifact size mismatch: expected {expected_size}, found {size}")
        if expected_sha and actual_sha != expected_sha:
            raise ValueError(
                f"artifact SHA-256 mismatch: expected {expected_sha}, found {actual_sha}"
            )

        return JSONResponse(
            {
                "success": True,
                "project_id": project_id,
                "path": target.as_posix(),
                "size_bytes": size,
                "sha256": actual_sha,
                "transfer_method": "direct_raw",
            }
        )
    except ValueError as exc:
        target.unlink(missing_ok=True)
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception:
        target.unlink(missing_ok=True)
        return JSONResponse({"error": "direct artifact upload failed"}, status_code=500)
