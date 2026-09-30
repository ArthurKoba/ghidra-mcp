"""Project-scoped routing for a pool of headless Ghidra workers."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import posixpath
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from . import session_settings, state, transport
from .config import DEFAULT_TCP_URL, logger
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
    queued: int = 0
    running: int = 0
    current_operation: str | None = None
    last_used_at: float = 0.0
    enabled: bool = True
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
_project_workers: dict[str, frozenset[str]] = {}
_queue_locks: dict[str, asyncio.Lock] = {}
_sweeper_stop = threading.Event()
_sweeper_thread: threading.Thread | None = None


def _idle_timeout_seconds() -> float:
    return session_settings.idle_timeout_seconds()


def _idle_sweep_interval_seconds() -> float:
    raw = os.getenv("GHIDRA_MCP_PROJECT_IDLE_SWEEP_SECONDS", "30").strip()
    try:
        return max(1.0, float(raw))
    except ValueError:
        return 30.0


def _touch(slot: WorkerSlot) -> None:
    slot.last_used_at = time.time()


def _timestamp(value: float) -> str | None:
    if value <= 0:
        return None
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _queue_lock(worker_url: str) -> asyncio.Lock:
    lock = _queue_locks.get(worker_url)
    if lock is None:
        lock = asyncio.Lock()
        _queue_locks[worker_url] = lock
    return lock


def _ensure_idle_sweeper_locked() -> None:
    global _sweeper_thread, _sweeper_stop
    if _idle_timeout_seconds() <= 0:
        return
    if _sweeper_thread is not None and _sweeper_thread.is_alive():
        return
    _sweeper_stop = threading.Event()

    def _loop() -> None:
        while not _sweeper_stop.wait(_idle_sweep_interval_seconds()):
            try:
                released = release_idle_sessions()
                if released:
                    logger.info("Auto-released idle project sessions: %s", released)
            except Exception:
                logger.exception("Idle project-session sweep failed")

    _sweeper_thread = threading.Thread(
        target=_loop,
        name="GhidraMCP-ProjectIdleSweep",
        daemon=True,
    )
    _sweeper_thread.start()


def refresh_idle_sweeper() -> None:
    with _lock:
        _ensure_idle_sweeper_locked()


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
    _ensure_idle_sweeper_locked()


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
    global _catalog, _project_workers
    _sync_worker_config_locked()
    records_by_id: dict[str, ProjectRecord] = {}
    workers_by_project: dict[str, set[str]] = {}
    errors: list[str] = []
    params = {"searchDir": search_dir} if search_dir else None

    for url in _configured_urls:
        try:
            records = _project_records(
                _request(url, "GET", "/list_projects", params=params, timeout=20)
            )
        except Exception as exc:
            errors.append(f"{url}: {exc}")
            continue
        for record in records:
            records_by_id[record.project_id] = record
            workers_by_project.setdefault(record.project_id, set()).add(url)

    if not workers_by_project and len(errors) == len(_configured_urls):
        raise ProjectSessionError(
            "No healthy Ghidra worker could list projects: " + "; ".join(errors)
        )
    _catalog = records_by_id
    _project_workers = {key: frozenset(urls) for key, urls in workers_by_project.items()}
    return _catalog

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


def _slot_status(index: int, slot: WorkerSlot) -> dict[str, Any]:
    now = time.time()
    idle_seconds = (
        max(0.0, now - slot.last_used_at)
        if slot.project_id is not None and slot.last_used_at > 0
        else None
    )
    timeout = _idle_timeout_seconds()
    return {
        "worker_index": index,
        "project_id": slot.project_id,
        "project_name": slot.project_name,
        "in_flight": slot.in_flight,
        "queued": slot.queued,
        "running": bool(slot.running),
        "current_operation": slot.current_operation,
        "last_used_at": _timestamp(slot.last_used_at),
        "idle_seconds": round(idle_seconds, 3) if idle_seconds is not None else None,
        "idle_timeout_seconds": timeout,
        "enabled": slot.enabled,
        "auto_release_eligible": bool(
            slot.project_id
            and timeout > 0
            and slot.in_flight == 0
            and idle_seconds is not None
            and idle_seconds >= timeout
        ),
        "healthy": slot.error is None,
        "error": slot.error,
    }


def _status_locked() -> list[dict[str, Any]]:
    return [
        _slot_status(index, slot)
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
                    "queued": slot.queued if slot else 0,
                    "running": bool(slot.running) if slot else False,
                    "current_operation": slot.current_operation if slot else None,
                    "last_used_at": _timestamp(slot.last_used_at) if slot else None,
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
    _touch(slot)


def checkout(project_id: str) -> ProjectLease:
    with _lock:
        record = _resolve_project_locked(project_id)
        _reconcile_slots_locked()

        slot = next((item for item in _slots.values() if item.project_id == record.project_id), None)
        if slot is None:
            eligible_urls = _project_workers.get(record.project_id, frozenset())
            candidates = [
                item for item in _slots.values()
                if item.url in eligible_urls
                and item.enabled
                and item.project_id is None
                and item.project_name is None
                and item.error is None
            ]
            if not candidates:
                raise ProjectPoolExhaustedError(
                    "All Ghidra workers are occupied or unavailable for this project. "
                    f"Eligible workers: {sorted(eligible_urls)}. Workers: {_status_locked()}"
                )
            errors: list[str] = []
            for candidate in candidates:
                try:
                    _open_on_slot_locked(candidate, record)
                    slot = candidate
                    break
                except ProjectSessionError as exc:
                    errors.append(f"{candidate.url}: {exc}")
            if slot is None:
                raise ProjectSessionError(
                    f"No eligible Ghidra worker could open project {record.name!r}: "
                    + "; ".join(errors)
                )

        slot.in_flight += 1
        _touch(slot)
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
        _touch(slot)


def _mark_queued(worker_url: str) -> None:
    with _lock:
        slot = _slots.get(worker_url)
        if slot is None:
            return
        slot.queued += 1
        _touch(slot)


def _mark_cancelled(worker_url: str) -> None:
    with _lock:
        slot = _slots.get(worker_url)
        if slot is None:
            return
        slot.queued = max(0, slot.queued - 1)
        _touch(slot)


def _mark_running(worker_url: str, operation: str) -> None:
    with _lock:
        slot = _slots.get(worker_url)
        if slot is None:
            return
        slot.queued = max(0, slot.queued - 1)
        slot.running = 1
        slot.current_operation = operation
        _touch(slot)


def _mark_finished(worker_url: str) -> None:
    with _lock:
        slot = _slots.get(worker_url)
        if slot is None:
            return
        slot.running = 0
        slot.current_operation = None
        _touch(slot)


async def acquire_project_operation(project_id: str, operation: str) -> ProjectLease:
    """Acquire the FIFO execution slot for one project/worker."""

    lease = await state.run_in_worker(checkout, project_id)
    lock = _queue_lock(lease.worker_url)
    await state.run_in_worker(_mark_queued, lease.worker_url)
    try:
        await lock.acquire()
    except BaseException:
        await state.run_in_worker(_mark_cancelled, lease.worker_url)
        await state.run_in_worker(release_lease, lease)
        raise
    await state.run_in_worker(_mark_running, lease.worker_url, operation)
    return lease


async def release_project_operation(lease: ProjectLease) -> None:
    """Release a project FIFO slot and its worker lease."""

    await state.run_in_worker(_mark_finished, lease.worker_url)
    lock = _queue_locks.get(lease.worker_url)
    if lock is not None and lock.locked():
        lock.release()
    await state.run_in_worker(release_lease, lease)


def release_idle_sessions(now: float | None = None) -> list[str]:
    """Close project sessions that have been idle past the configured timeout."""

    released: list[str] = []
    timeout = _idle_timeout_seconds()
    if timeout <= 0:
        return released
    current = time.time() if now is None else now
    with _lock:
        _reconcile_slots_locked()
        for slot in _slots.values():
            if (
                slot.project_id is None
                or slot.in_flight != 0
                or slot.queued != 0
                or slot.running != 0
                or slot.last_used_at <= 0
                or current - slot.last_used_at < timeout
            ):
                continue
            project_id = slot.project_id
            try:
                _request(
                    slot.url,
                    "POST",
                    "/close_project",
                    json_data={"dry_run": False},
                    timeout=30,
                )
            except Exception as exc:
                slot.error = str(exc)
                continue
            slot.project_id = None
            slot.project_name = None
            slot.current_operation = None
            slot.last_used_at = 0.0
            slot.error = None
            released.append(project_id)
    return released


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
            "queued": slot.queued if slot else 0,
            "running": bool(slot.running) if slot else False,
            "current_operation": slot.current_operation if slot else None,
            "last_used_at": _timestamp(slot.last_used_at) if slot else None,
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
        if slot.in_flight or slot.queued or slot.running:
            raise ProjectBusyError(
                f"Project {record.project_id} is busy: "
                f"in_flight={slot.in_flight}, queued={slot.queued}, running={slot.running}"
            )
        if close_project:
            _request(slot.url, "POST", "/close_project", json_data={"dry_run": False}, timeout=30)
        slot.project_id = None
        slot.project_name = None
        slot.current_operation = None
        slot.last_used_at = 0.0
        slot.error = None
        return {
            "project_id": record.project_id,
            "released": True,
            "closed": close_project,
        }



def _idle_slot_locked() -> WorkerSlot:
    _reconcile_slots_locked()
    slot = next(
        (
            item
            for item in _slots.values()
            if item.enabled
            and item.project_id is None
            and item.project_name is None
            and item.in_flight == 0
            and item.error is None
        ),
        None,
    )
    if slot is None:
        raise ProjectPoolExhaustedError(
            "No idle Ghidra worker is available. "
            "Release an unused project session or increase GHIDRA_MCP_WORKER_COUNT. "
            f"Workers: {_status_locked()}"
        )
    return slot


def create_project(name: str, parent_dir: str = "") -> dict[str, Any]:
    name = name.strip()
    if not name:
        raise ProjectSessionError("name is required")
    with _lock:
        _refresh_catalog_locked(parent_dir)
        slot = _idle_slot_locked()
        value = _request(
            slot.url,
            "POST",
            "/create_project",
            json_data={"name": name, "parentDir": parent_dir},
            timeout=60,
        )
        if not isinstance(value, dict):
            raise ProjectSessionError("Ghidra create_project returned an invalid payload")
        path = str(value.get("project_path", "")).strip()
        if not path:
            raise ProjectSessionError("Ghidra create_project did not return project_path")
        record = ProjectRecord(
            project_id=project_id_for_path(path),
            name=str(value.get("name", name)).strip() or name,
            path=posixpath.normpath(path),
        )
        _catalog[record.project_id] = record
        slot.project_id = record.project_id
        slot.project_name = record.name
        slot.error = None
        _touch(slot)
        return {
            "project_id": record.project_id,
            "name": record.name,
            "path": record.path,
            "session": "active",
            "worker_index": list(_slots).index(slot.url),
        }


def delete_project(project_id: str) -> dict[str, Any]:
    with _lock:
        record = _resolve_project_locked(project_id)
        _reconcile_slots_locked()
        slot = next((item for item in _slots.values() if item.project_id == record.project_id), None)
        if slot is not None:
            if slot.in_flight:
                raise ProjectBusyError(
                    f"Project {record.project_id} has {slot.in_flight} in-flight request(s)"
                )
            _request(slot.url, "POST", "/close_project", json_data={}, timeout=30)
            slot.project_id = None
            slot.project_name = None
            slot.error = None

        worker = slot or _idle_slot_locked()
        _request(
            worker.url,
            "POST",
            "/delete_project",
            json_data={"projectPath": record.path},
            timeout=60,
        )
        _catalog.pop(record.project_id, None)
        return {
            "project_id": record.project_id,
            "name": record.name,
            "path": record.path,
            "deleted": True,
        }


def reset_for_tests() -> None:
    global _configured_urls, _slots, _catalog, _project_workers, _queue_locks, _sweeper_thread
    _sweeper_stop.set()
    thread = _sweeper_thread
    if thread is not None and thread.is_alive():
        thread.join(timeout=0.2)
    with _lock:
        _configured_urls = ()
        _slots = {}
        _catalog = {}
        _project_workers = {}
        _queue_locks = {}
        _sweeper_thread = None
