"""Project-scoped routing for a pool of headless Ghidra workers."""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import threading
from dataclasses import dataclass
from typing import Any

from . import state, transport
from .config import DEFAULT_TCP_URL
from .validation import validate_server_url


class ProjectSessionError(RuntimeError):
    """Base error for project/session routing."""


class ProjectNotFoundError(ProjectSessionError):
    pass


class ProjectPoolExhaustedError(ProjectSessionError):
    pass


class ProjectBusyError(ProjectSessionError):
    pass


@dataclass(frozen=True)
class ProjectRecord:
    project_id: str
    name: str
    path: str


@dataclass
class WorkerSlot:
    url: str
    project_id: str | None = None
    project_name: str | None = None
    in_flight: int = 0
    error: str | None = None


@dataclass(frozen=True)
class ProjectLease:
    project_id: str
    worker_url: str
    snapshot: state.ConnectionSnapshot


_lock = threading.RLock()
_slots: dict[str, WorkerSlot] = {}
_configured_urls: tuple[str, ...] = ()
_catalog: dict[str, ProjectRecord] = {}


def _decode_payload(text: str) -> Any:
    value: Any = json.loads(text)
    for _ in range(8):
        if isinstance(value, dict) and "data" in value:
            value = value["data"]
            continue
        if isinstance(value, dict) and "result" in value:
            value = value["result"]
            continue
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                return value
            continue
        return value
    return value


def _normalize_url(url: str) -> str:
    return url.strip().rstrip("/")


def configured_worker_urls() -> tuple[str, ...]:
    raw = os.getenv("GHIDRA_MCP_WORKER_URLS", "").strip()
    if raw:
        candidates = [_normalize_url(item) for item in raw.split(",") if item.strip()]
    else:
        fallback = os.getenv("GHIDRA_MCP_URL", "").strip() or DEFAULT_TCP_URL
        candidates = [_normalize_url(fallback)]

    urls: list[str] = []
    for url in candidates:
        if url in urls:
            continue
        if not validate_server_url(url):
            raise ProjectSessionError(
                f"Invalid/untrusted Ghidra worker URL: {url}. "
                "Configure GHIDRA_MCP_TRUSTED_HOSTS for Docker DNS names."
            )
        urls.append(url)
    if not urls:
        raise ProjectSessionError("No Ghidra workers configured")
    return tuple(urls)


def _sync_worker_config_locked() -> None:
    global _configured_urls, _slots
    urls = configured_worker_urls()
    if urls == _configured_urls:
        return
    old = _slots
    _slots = {url: old.get(url, WorkerSlot(url=url)) for url in urls}
    _configured_urls = urls


def _snapshot(url: str, project_name: str | None = None) -> state.ConnectionSnapshot:
    return state.build_connection_snapshot(
        mode="tcp",
        active_tcp=url,
        connected_project=project_name,
    )


def _request(
    url: str,
    method: str,
    endpoint: str,
    *,
    params: dict[str, Any] | None = None,
    json_data: dict[str, Any] | None = None,
    timeout: int = 30,
) -> Any:
    text, status = transport.do_request(
        method,
        endpoint,
        params=params,
        json_data=json_data,
        timeout=timeout,
        connection=_snapshot(url),
    )
    if status != 200:
        raise ProjectSessionError(f"{endpoint} on {url} returned HTTP {status}: {text.strip()}")
    value = _decode_payload(text)
    if isinstance(value, dict):
        error = str(value.get("error", "")).strip()
        if error:
            raise ProjectSessionError(f"{endpoint} on {url} failed: {error}")
        if value.get("success") is False:
            raise ProjectSessionError(f"{endpoint} on {url} failed")
    return value


def project_id_for_path(path: str) -> str:
    canonical = posixpath.normpath(path.strip())
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
    return f"ghp_{digest}"


def _project_records(value: Any) -> list[ProjectRecord]:
    if isinstance(value, dict) and isinstance(value.get("projects"), list):
        value = value["projects"]
    if not isinstance(value, list):
        raise ProjectSessionError("Ghidra list_projects returned an invalid payload")

    records: list[ProjectRecord] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        path = str(item.get("path", "")).strip()
        if not name or not path:
            continue
        canonical = posixpath.normpath(path)
        records.append(
            ProjectRecord(
                project_id=project_id_for_path(canonical),
                name=name,
                path=canonical,
            )
        )
    return records


def _refresh_catalog_locked(search_dir: str = "") -> dict[str, ProjectRecord]:
    global _catalog
    _sync_worker_config_locked()
    errors: list[str] = []
    params = {"searchDir": search_dir} if search_dir else None
    for url in _configured_urls:
        try:
            value = _request(url, "GET", "/list_projects", params=params, timeout=20)
            records = _project_records(value)
            _catalog = {record.project_id: record for record in records}
            return _catalog
        except Exception as exc:
            errors.append(f"{url}: {exc}")
    raise ProjectSessionError("No healthy Ghidra worker could list projects: " + "; ".join(errors))


def _project_info(url: str) -> dict[str, Any]:
    value = _request(url, "GET", "/get_project_info", timeout=10)
    if not isinstance(value, dict):
        raise ProjectSessionError(f"get_project_info on {url} returned an invalid payload")
    return value


def _reconcile_slots_locked() -> None:
    _sync_worker_config_locked()
    if not _catalog:
        _refresh_catalog_locked()

    by_name: dict[str, list[ProjectRecord]] = {}
    for record in _catalog.values():
        by_name.setdefault(record.name, []).append(record)

    for slot in _slots.values():
        try:
            info = _project_info(slot.url)
            slot.error = None
        except Exception as exc:
            slot.error = str(exc)
            continue

        if not info.get("has_project"):
            if slot.in_flight == 0:
                slot.project_id = None
                slot.project_name = None
            continue

        name = str(info.get("project_name", "")).strip()
        slot.project_name = name or None
        if slot.project_id:
            record = _catalog.get(slot.project_id)
            if record and record.name == name:
                continue

        matches = by_name.get(name, [])
        if len(matches) == 1:
            slot.project_id = matches[0].project_id
        else:
            # Occupied, but intentionally not guessed when names are ambiguous.
            slot.project_id = None


def _status_locked() -> list[dict[str, Any]]:
    return [
        {
            "worker_index": index,
            "project_id": slot.project_id,
            "project_name": slot.project_name,
            "in_flight": slot.in_flight,
            "healthy": slot.error is None,
            "error": slot.error,
        }
        for index, slot in enumerate(_slots.values())
    ]


def list_projects(query: str = "", search_dir: str = "") -> dict[str, Any]:
    with _lock:
        catalog = _refresh_catalog_locked(search_dir)
        _reconcile_slots_locked()
        needle = query.strip().casefold()
        items: list[dict[str, Any]] = []
        for record in sorted(catalog.values(), key=lambda item: (item.name.casefold(), item.path)):
            if needle and needle not in record.name.casefold() and needle not in record.path.casefold() and needle not in record.project_id:
                continue
            slot = next((s for s in _slots.values() if s.project_id == record.project_id), None)
            items.append(
                {
                    "project_id": record.project_id,
                    "name": record.name,
                    "path": record.path,
                    "session": "active" if slot else "available",
                    "in_flight": slot.in_flight if slot else 0,
                }
            )
        return {
            "projects": items,
            "count": len(items),
            "worker_count": len(_slots),
            "workers": _status_locked(),
        }


def _resolve_project_locked(project_id: str) -> ProjectRecord:
    project_id = project_id.strip()
    if not project_id:
        raise ProjectNotFoundError("project_id is required")
    if project_id not in _catalog:
        _refresh_catalog_locked()
    record = _catalog.get(project_id)
    if record is None:
        raise ProjectNotFoundError(
            f"Unknown project_id: {project_id}. Call list_projects() to obtain a current project_id."
        )
    return record


def find_project(selector: str) -> ProjectRecord:
    with _lock:
        catalog = _refresh_catalog_locked()
        selector = selector.strip()
        if selector in catalog:
            return catalog[selector]

        exact = [record for record in catalog.values() if record.name == selector or record.path == selector]
        if len(exact) == 1:
            return exact[0]
        if len(exact) > 1:
            raise ProjectSessionError(
                f"Project selector '{selector}' is ambiguous. Use project_id from list_projects()."
            )

        needle = selector.casefold()
        partial = [
            record
            for record in catalog.values()
            if needle and (needle in record.name.casefold() or needle in record.path.casefold())
        ]
        if len(partial) == 1:
            return partial[0]
        if len(partial) > 1:
            raise ProjectSessionError(
                f"Project selector '{selector}' matches multiple projects. Use project_id from list_projects()."
            )
        raise ProjectNotFoundError(f"No project matching '{selector}'")


def _open_on_slot_locked(slot: WorkerSlot, record: ProjectRecord) -> None:
    if slot.project_name or slot.project_id:
        raise ProjectBusyError(f"Worker {slot.url} is already assigned to {slot.project_name or slot.project_id}")
    _request(
        slot.url,
        "POST",
        "/open_project",
        json_data={"path": record.path, "dry_run": False},
        timeout=60,
    )
    info = _project_info(slot.url)
    if not info.get("has_project") or str(info.get("project_name", "")).strip() != record.name:
        raise ProjectSessionError(
            f"Worker {slot.url} did not open requested project {record.name}"
        )
    slot.project_id = record.project_id
    slot.project_name = record.name
    slot.error = None


def checkout(project_id: str) -> ProjectLease:
    with _lock:
        record = _resolve_project_locked(project_id)
        _reconcile_slots_locked()

        slot = next((item for item in _slots.values() if item.project_id == record.project_id), None)
        if slot is None:
            slot = next(
                (
                    item
                    for item in _slots.values()
                    if item.project_id is None and item.project_name is None and item.error is None
                ),
                None,
            )
            if slot is None:
                raise ProjectPoolExhaustedError(
                    "All Ghidra workers are occupied. "
                    "Release an unused project session or increase GHIDRA_MCP_WORKER_COUNT. "
                    f"Workers: {_status_locked()}"
                )
            _open_on_slot_locked(slot, record)

        slot.in_flight += 1
        return ProjectLease(
            project_id=record.project_id,
            worker_url=slot.url,
            snapshot=_snapshot(slot.url, record.name),
        )


def release_lease(lease: ProjectLease) -> None:
    with _lock:
        slot = _slots.get(lease.worker_url)
        if slot is None or slot.project_id != lease.project_id:
            return
        slot.in_flight = max(0, slot.in_flight - 1)


def ensure_session(project_id: str) -> dict[str, Any]:
    lease = checkout(project_id)
    try:
        with _lock:
            record = _resolve_project_locked(project_id)
            slot = _slots[lease.worker_url]
            return {
                "project_id": record.project_id,
                "name": record.name,
                "path": record.path,
                "session": "active",
                "in_flight": slot.in_flight,
                "worker_index": list(_slots).index(slot.url),
            }
    finally:
        release_lease(lease)


def session_info(project_id: str) -> dict[str, Any]:
    with _lock:
        record = _resolve_project_locked(project_id)
        _reconcile_slots_locked()
        slot = next((item for item in _slots.values() if item.project_id == record.project_id), None)
        return {
            "project_id": record.project_id,
            "name": record.name,
            "path": record.path,
            "session": "active" if slot else "available",
            "in_flight": slot.in_flight if slot else 0,
            "worker_index": list(_slots).index(slot.url) if slot else None,
        }


def release_project_session(project_id: str, close_project: bool = True) -> dict[str, Any]:
    with _lock:
        record = _resolve_project_locked(project_id)
        _reconcile_slots_locked()
        slot = next((item for item in _slots.values() if item.project_id == record.project_id), None)
        if slot is None:
            return {
                "project_id": record.project_id,
                "released": False,
                "reason": "not_active",
            }
        if slot.in_flight:
            raise ProjectBusyError(
                f"Project {record.project_id} has {slot.in_flight} in-flight request(s)"
            )
        if close_project:
            _request(slot.url, "POST", "/close_project", json_data={"dry_run": False}, timeout=30)
        slot.project_id = None
        slot.project_name = None
        slot.error = None
        return {
            "project_id": record.project_id,
            "released": True,
            "closed": close_project,
        }


def reset_for_tests() -> None:
    global _configured_urls, _slots, _catalog
    with _lock:
        _configured_urls = ()
        _slots = {}
        _catalog = {}
