"""Worker-slot maintenance and recovery controls for the headless project router."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from . import operation_queue, project_sessions, state, transport


def _slot(worker_index: int) -> project_sessions.WorkerSlot:
    with project_sessions._lock:
        project_sessions._sync_worker_config_locked()
        slots = list(project_sessions._slots.values())
        if worker_index < 0 or worker_index >= len(slots):
            raise project_sessions.ProjectSessionError(
                f"Unknown worker_index {worker_index}; configured workers: {len(slots)}"
            )
        return slots[worker_index]


def set_worker_enabled(
    worker_index: int,
    enabled: bool,
    close_project: bool = True,
) -> dict[str, Any]:
    """Enable or disable one worker slot for project routing.

    Disabling does not kill the JVM. It removes the worker from routing and,
    when idle, optionally closes its active project session first.
    """

    with project_sessions._lock:
        slot = _slot(worker_index)

        if enabled:
            slot.enabled = True
            return {
                **project_sessions._slot_status(worker_index, slot),
                "changed": True,
            }

        if slot.in_flight or slot.queued or slot.running:
            raise project_sessions.ProjectBusyError(
                f"Worker {worker_index} is busy: "
                f"in_flight={slot.in_flight}, queued={slot.queued}, running={slot.running}"
            )

        if close_project and (slot.project_id or slot.project_name):
            project_sessions._request(
                slot.url,
                "POST",
                "/close_project",
                json_data={"dry_run": False},
                timeout=30,
            )
            slot.project_id = None
            slot.project_name = None
            slot.current_operation = None
            slot.last_used_at = 0.0

        slot.enabled = False
        return {
            **project_sessions._slot_status(worker_index, slot),
            "changed": True,
        }


async def clear_worker_queue(worker_index: int) -> dict[str, Any]:
    """Cancel bridge requests waiting behind the current operation on one worker."""

    slot = await state.run_in_worker(_slot, worker_index)
    cancelled = await operation_queue.cancel(
        slot.url,
        include_running=False,
    )
    with project_sessions._lock:
        current = project_sessions._slots[slot.url]
        return {
            **project_sessions._slot_status(worker_index, current),
            **cancelled,
        }


def _prepare_recovery(worker_index: int) -> tuple[str, bool, str | None, str | None]:
    with project_sessions._lock:
        slot = _slot(worker_index)
        previous_enabled = slot.enabled
        project_id = slot.project_id
        project_name = slot.project_name
        slot.enabled = False
        slot.error = "recovering"
        return slot.url, previous_enabled, project_id, project_name


def _reset_slot_after_cancel(worker_url: str) -> None:
    with project_sessions._lock:
        slot = project_sessions._slots[worker_url]
        slot.in_flight = 0
        slot.queued = 0
        slot.running = 0
        slot.current_operation = None
        slot.project_id = None
        slot.project_name = None
        slot.last_used_at = 0.0
        operation_queue.reset_worker(worker_url)


def _request_worker_exit(worker_url: str) -> None:
    project_sessions._request(
        worker_url,
        "POST",
        "/exit_ghidra",
        timeout=5,
    )


def _worker_healthy(worker_url: str) -> bool:
    try:
        text, status = transport.do_request(
            "GET",
            "/check_connection",
            timeout=2,
            connection=project_sessions._snapshot(worker_url),
        )
    except Exception:
        return False
    return status == 200 and bool(text.strip())


def _finish_recovery(worker_index: int, worker_url: str, enabled: bool) -> dict[str, Any]:
    with project_sessions._lock:
        slot = project_sessions._slots[worker_url]
        slot.enabled = enabled
        slot.error = None
        return project_sessions._slot_status(worker_index, slot)


async def recover_worker(
    worker_index: int,
    *,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Cancel active/queued requests and restart exactly one headless worker JVM."""

    worker_url, previous_enabled, project_id, project_name = await state.run_in_worker(
        _prepare_recovery,
        worker_index,
    )
    cancelled = await operation_queue.cancel(
        worker_url,
        include_running=True,
    )
    await state.run_in_worker(_reset_slot_after_cancel, worker_url)

    exit_error = ""
    try:
        await state.run_in_worker(_request_worker_exit, worker_url)
    except Exception as exc:
        exit_error = str(exc)

    # The native endpoint exits about 500 ms after acknowledging the request.
    await asyncio.sleep(0.75)
    deadline = time.monotonic() + max(2.0, float(timeout_seconds))
    while time.monotonic() < deadline:
        if await state.run_in_worker(_worker_healthy, worker_url):
            status = await state.run_in_worker(
                _finish_recovery,
                worker_index,
                worker_url,
                previous_enabled,
            )
            return {
                **status,
                **cancelled,
                "recovered": True,
                "previous_project_id": project_id,
                "previous_project_name": project_name,
                "exit_error": exit_error or None,
            }
        await asyncio.sleep(0.25)

    with project_sessions._lock:
        slot = project_sessions._slots[worker_url]
        slot.error = "worker recovery timed out"
    raise project_sessions.ProjectSessionError(f"Worker {worker_index} did not recover within {timeout_seconds:.1f}s")
