"""Worker-slot maintenance and recovery controls for the headless project router."""

from __future__ import annotations

import asyncio
import os
import stat
import time
from pathlib import Path
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


def _worker_control_fifo() -> Path:
    return Path(
        os.getenv(
            "GHIDRA_MCP_WORKER_CONTROL_FIFO",
            "/data/bridge/worker-control.fifo",
        )
    )


def _request_worker_restart(worker_index: int, worker_url: str) -> str:
    fifo = _worker_control_fifo()
    try:
        mode = fifo.stat().st_mode
    except OSError:
        mode = 0
    if stat.S_ISFIFO(mode):
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        try:
            os.write(fd, f"restart {worker_index}\n".encode("ascii"))
        finally:
            os.close(fd)
        return "supervisor-sigkill"

    # Non-Docker/manual fallback where no shared supervisor control FIFO exists.
    project_sessions._request(
        worker_url,
        "POST",
        "/exit_ghidra",
        timeout=1,
    )
    return "native-exit"


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
    timeout_seconds: float = 4.0,
) -> dict[str, Any]:
    """Hard-restart exactly one worker and restore it within a bounded fast path."""

    budget = min(4.0, max(1.0, float(timeout_seconds)))
    started = time.monotonic()
    worker_url, previous_enabled, project_id, project_name = await state.run_in_worker(
        _prepare_recovery,
        worker_index,
    )
    cancelled = await operation_queue.cancel(
        worker_url,
        include_running=True,
    )
    await state.run_in_worker(_reset_slot_after_cancel, worker_url)

    restart_method = await state.run_in_worker(
        _request_worker_restart,
        worker_index,
        worker_url,
    )

    # Do not accept the old JVM as recovered. Observe the port go down once,
    # then require the replacement JVM to become healthy within the budget.
    observed_down = False
    deadline = started + budget
    while time.monotonic() < deadline:
        healthy = await state.run_in_worker(_worker_healthy, worker_url)
        if not healthy:
            observed_down = True
        elif observed_down:
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
                "restart_method": restart_method,
                "recovery_ms": round((time.monotonic() - started) * 1000, 1),
                "previous_project_id": project_id,
                "previous_project_name": project_name,
            }
        await asyncio.sleep(0.05)

    with project_sessions._lock:
        slot = project_sessions._slots[worker_url]
        slot.error = f"worker recovery exceeded {budget:.1f}s budget"
    raise project_sessions.ProjectSessionError(f"Worker {worker_index} did not recover within {budget:.1f}s")
