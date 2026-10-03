"""Async FIFO/task bookkeeping for project-scoped worker operations."""

from __future__ import annotations

import asyncio
from typing import Any

_locks: dict[str, asyncio.Lock] = {}
_tasks: dict[str, dict[asyncio.Task[Any], str]] = {}


def lock(worker_url: str) -> asyncio.Lock:
    current = _locks.get(worker_url)
    if current is None:
        current = asyncio.Lock()
        _locks[worker_url] = current
    return current


def track(worker_url: str, state_name: str) -> None:
    task = asyncio.current_task()
    if task is not None:
        _tasks.setdefault(worker_url, {})[task] = state_name


def set_state(worker_url: str, state_name: str) -> None:
    task = asyncio.current_task()
    if task is None:
        return
    tasks = _tasks.get(worker_url)
    if tasks is not None and task in tasks:
        tasks[task] = state_name


def untrack(worker_url: str) -> None:
    task = asyncio.current_task()
    if task is None:
        return
    tasks = _tasks.get(worker_url)
    if tasks is None:
        return
    tasks.pop(task, None)
    if not tasks:
        _tasks.pop(worker_url, None)


async def cancel(worker_url: str, *, include_running: bool) -> dict[str, int]:
    tasks = _tasks.get(worker_url, {})
    current = asyncio.current_task()
    selected = [
        task
        for task, task_state in list(tasks.items())
        if task is not current and (include_running or task_state == "queued") and not task.done()
    ]
    queued = sum(1 for task in selected if tasks.get(task) == "queued")
    running = sum(1 for task in selected if tasks.get(task) == "running")
    for task in selected:
        task.cancel()
    if selected:
        await asyncio.gather(*selected, return_exceptions=True)
    return {
        "cancelled_total": len(selected),
        "cancelled_queued": queued,
        "cancelled_running": running,
    }


def release_lock(worker_url: str) -> None:
    current = _locks.get(worker_url)
    if current is not None and current.locked():
        current.release()


def reset_worker(worker_url: str) -> None:
    _locks.pop(worker_url, None)
    tasks = _tasks.get(worker_url)
    if not tasks:
        _tasks.pop(worker_url, None)


def reset_all() -> None:
    _locks.clear()
    _tasks.clear()
