"""Worker-slot maintenance controls for the headless project router."""

from __future__ import annotations

from typing import Any

from . import project_sessions


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
        project_sessions._sync_worker_config_locked()
        slots = list(project_sessions._slots.values())
        if worker_index < 0 or worker_index >= len(slots):
            raise project_sessions.ProjectSessionError(
                f"Unknown worker_index {worker_index}; configured workers: {len(slots)}"
            )
        slot = slots[worker_index]

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
