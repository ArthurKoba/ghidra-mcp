import asyncio
import time
import json
from unittest.mock import patch

import pytest

from bridge_mcp_ghidra import project_sessions
from bridge_mcp_ghidra import worker_control

PROJECTS = [
    {"name": "alpha", "path": "/projects/alpha.gpr"},
    {"name": "beta", "path": "/projects/beta.gpr"},
    {"name": "gamma", "path": "/projects/gamma.gpr"},
]


@pytest.fixture(autouse=True)
def reset_sessions(monkeypatch):
    monkeypatch.setenv(
        "GHIDRA_MCP_WORKER_URLS",
        "http://127.0.0.1:8089,http://127.0.0.1:8090",
    )
    monkeypatch.setenv("GHIDRA_MCP_PROJECT_IDLE_SWEEP_SECONDS", "3600")
    project_sessions.reset_for_tests()
    yield
    project_sessions.reset_for_tests()


@pytest.fixture
def fake_workers():
    state = {
        "http://127.0.0.1:8089": None,
        "http://127.0.0.1:8090": None,
    }
    by_path = {item["path"]: item["name"] for item in PROJECTS}

    def do_request(
        method,
        endpoint,
        params=None,
        json_data=None,
        timeout=30,
        connection=None,
    ):
        url = connection.active_tcp
        if endpoint == "/list_projects":
            return json.dumps(PROJECTS), 200
        if endpoint == "/get_project_info":
            name = state[url]
            return (
                json.dumps(
                    {
                        "data": {
                            "has_project": name is not None,
                            "project_name": name or "",
                        }
                    }
                ),
                200,
            )
        if endpoint == "/open_project":
            path = json_data["path"]
            state[url] = by_path[path]
            return json.dumps({"data": {"success": True, "project": state[url]}}), 200
        if endpoint == "/close_project":
            closed = state[url]
            state[url] = None
            return json.dumps({"data": {"success": True, "closed": closed}}), 200
        raise AssertionError(f"unexpected request: {method} {endpoint}")

    with patch.object(project_sessions.transport, "do_request", side_effect=do_request):
        yield state


def _ids():
    listed = project_sessions.list_projects()
    return {item["name"]: item["project_id"] for item in listed["projects"]}


def test_project_id_is_stable_and_path_scoped():
    one = project_sessions.project_id_for_path("/projects/alpha.gpr")
    two = project_sessions.project_id_for_path("/projects/alpha.gpr")
    other = project_sessions.project_id_for_path("/projects/nested/alpha.gpr")

    assert one == two
    assert one.startswith("ghp_")
    assert len(one) == 28
    assert other != one


def test_two_projects_bind_to_two_workers_without_global_switch(fake_workers):
    ids = _ids()

    alpha = project_sessions.checkout(ids["alpha"])
    beta = project_sessions.checkout(ids["beta"])
    try:
        assert alpha.worker_url == "http://127.0.0.1:8089"
        assert beta.worker_url == "http://127.0.0.1:8090"
        assert alpha.snapshot.active_tcp != beta.snapshot.active_tcp
        assert alpha.snapshot.connected_project == "alpha"
        assert beta.snapshot.connected_project == "beta"
        assert fake_workers[alpha.worker_url] == "alpha"
        assert fake_workers[beta.worker_url] == "beta"
    finally:
        project_sessions.release_lease(alpha)
        project_sessions.release_lease(beta)


def test_same_project_stays_sticky_after_request_release(fake_workers):
    ids = _ids()

    first = project_sessions.checkout(ids["alpha"])
    first_url = first.worker_url
    project_sessions.release_lease(first)

    second = project_sessions.checkout(ids["alpha"])
    try:
        assert second.worker_url == first_url
        assert fake_workers[first_url] == "alpha"
    finally:
        project_sessions.release_lease(second)


def test_third_project_fails_explicitly_when_pool_is_fully_assigned(fake_workers):
    ids = _ids()

    alpha = project_sessions.checkout(ids["alpha"])
    beta = project_sessions.checkout(ids["beta"])
    project_sessions.release_lease(alpha)
    project_sessions.release_lease(beta)

    with pytest.raises(project_sessions.ProjectPoolExhaustedError, match="All Ghidra workers are occupied"):
        project_sessions.checkout(ids["gamma"])


def test_release_session_frees_worker_for_another_project(fake_workers):
    ids = _ids()

    alpha = project_sessions.checkout(ids["alpha"])
    beta = project_sessions.checkout(ids["beta"])
    project_sessions.release_lease(alpha)
    project_sessions.release_lease(beta)

    released = project_sessions.release_project_session(ids["alpha"])
    assert released["released"] is True
    assert fake_workers["http://127.0.0.1:8089"] is None

    gamma = project_sessions.checkout(ids["gamma"])
    try:
        assert gamma.worker_url == "http://127.0.0.1:8089"
        assert fake_workers[gamma.worker_url] == "gamma"
    finally:
        project_sessions.release_lease(gamma)


def test_release_refuses_to_close_project_with_in_flight_request(fake_workers):
    ids = _ids()
    lease = project_sessions.checkout(ids["alpha"])
    try:
        with pytest.raises(project_sessions.ProjectBusyError, match="busy"):
            project_sessions.release_project_session(ids["alpha"])
    finally:
        project_sessions.release_lease(lease)


def test_list_projects_reports_session_and_worker_state(fake_workers):
    ids = _ids()
    lease = project_sessions.checkout(ids["alpha"])
    try:
        listed = project_sessions.list_projects()
        alpha = next(item for item in listed["projects"] if item["name"] == "alpha")
        beta = next(item for item in listed["projects"] if item["name"] == "beta")

        assert alpha["project_id"] == ids["alpha"]
        assert alpha["session"] == "active"
        assert alpha["in_flight"] == 1
        assert beta["session"] == "available"
        assert listed["worker_count"] == 2
    finally:
        project_sessions.release_lease(lease)


@pytest.mark.asyncio
async def test_same_project_operations_run_fifo(fake_workers):
    ids = _ids()
    first = await project_sessions.acquire_project_operation(ids["alpha"], "first")
    order = []

    async def run(name):
        lease = await project_sessions.acquire_project_operation(ids["alpha"], name)
        try:
            order.append(name)
        finally:
            await project_sessions.release_project_operation(lease)

    second = asyncio.create_task(run("second"))
    for _ in range(50):
        info = project_sessions.session_info(ids["alpha"])
        if info["queued"] == 1:
            break
        await asyncio.sleep(0.01)
    else:
        raise AssertionError("second operation did not enter the FIFO queue")

    third = asyncio.create_task(run("third"))
    for _ in range(50):
        info = project_sessions.session_info(ids["alpha"])
        if info["queued"] == 2:
            break
        await asyncio.sleep(0.01)
    else:
        raise AssertionError("third operation did not enter the FIFO queue")

    assert info["running"] is True
    assert info["current_operation"] == "first"
    assert info["queued"] == 2
    assert info["in_flight"] == 3

    await project_sessions.release_project_operation(first)
    await asyncio.wait_for(asyncio.gather(second, third), timeout=2)

    assert order == ["second", "third"]
    info = project_sessions.session_info(ids["alpha"])
    assert info["running"] is False
    assert info["queued"] == 0
    assert info["in_flight"] == 0


@pytest.mark.asyncio
async def test_different_project_workers_run_in_parallel(fake_workers):
    ids = _ids()
    alpha = await project_sessions.acquire_project_operation(ids["alpha"], "alpha-op")
    beta = await project_sessions.acquire_project_operation(ids["beta"], "beta-op")
    try:
        alpha_info = project_sessions.session_info(ids["alpha"])
        beta_info = project_sessions.session_info(ids["beta"])
        assert alpha_info["running"] is True
        assert beta_info["running"] is True
        assert alpha.worker_url != beta.worker_url
    finally:
        await project_sessions.release_project_operation(alpha)
        await project_sessions.release_project_operation(beta)


def test_idle_project_session_is_auto_releasable(fake_workers, monkeypatch):
    monkeypatch.setenv("GHIDRA_MCP_PROJECT_IDLE_TIMEOUT_SECONDS", "1")
    ids = _ids()
    lease = project_sessions.checkout(ids["alpha"])
    project_sessions.release_lease(lease)

    released = project_sessions.release_idle_sessions(now=time.time() + 2)

    assert released == [ids["alpha"]]
    assert fake_workers["http://127.0.0.1:8089"] is None
    info = project_sessions.session_info(ids["alpha"])
    assert info["session"] == "available"


@pytest.mark.asyncio
async def test_manual_release_refuses_queued_project(fake_workers):
    ids = _ids()
    first = await project_sessions.acquire_project_operation(ids["alpha"], "first")

    waiter_started = asyncio.Event()

    async def wait_for_turn():
        waiter_started.set()
        lease = await project_sessions.acquire_project_operation(ids["alpha"], "second")
        await project_sessions.release_project_operation(lease)

    waiter = asyncio.create_task(wait_for_turn())
    await waiter_started.wait()
    await asyncio.sleep(0.05)
    try:
        with pytest.raises(project_sessions.ProjectBusyError, match="busy"):
            project_sessions.release_project_session(ids["alpha"])
    finally:
        await project_sessions.release_project_operation(first)
        await asyncio.wait_for(waiter, timeout=2)


def test_disabled_worker_is_removed_from_project_routing(fake_workers):
    ids = _ids()

    state = worker_control.set_worker_enabled(0, False)
    assert state["enabled"] is False

    beta = project_sessions.checkout(ids["beta"])
    try:
        assert beta.worker_url == "http://127.0.0.1:8090"
    finally:
        project_sessions.release_lease(beta)

    listed = project_sessions.list_projects()
    assert listed["workers"][0]["enabled"] is False
    assert listed["workers"][1]["enabled"] is True


def test_disabling_idle_worker_closes_its_project(fake_workers):
    ids = _ids()
    lease = project_sessions.checkout(ids["alpha"])
    project_sessions.release_lease(lease)
    assert fake_workers["http://127.0.0.1:8089"] == "alpha"

    state = worker_control.set_worker_enabled(0, False)

    assert state["enabled"] is False
    assert state["project_id"] is None
    assert fake_workers["http://127.0.0.1:8089"] is None


@pytest.mark.asyncio
async def test_disabling_busy_worker_is_rejected(fake_workers):
    ids = _ids()
    lease = await project_sessions.acquire_project_operation(ids["alpha"], "busy-op")
    try:
        with pytest.raises(project_sessions.ProjectBusyError, match="Worker 0 is busy"):
            worker_control.set_worker_enabled(0, False)
    finally:
        await project_sessions.release_project_operation(lease)

    state = worker_control.set_worker_enabled(0, True)
    assert state["enabled"] is True


def test_catalog_aggregates_worker_storage_and_routes_to_visible_worker():
    worker_projects = {
        "http://127.0.0.1:8089": [PROJECTS[0]],
        "http://127.0.0.1:8090": [PROJECTS[1]],
    }
    worker_state = {
        "http://127.0.0.1:8089": None,
        "http://127.0.0.1:8090": None,
    }

    def do_request(
        method,
        endpoint,
        params=None,
        json_data=None,
        timeout=30,
        connection=None,
    ):
        url = connection.active_tcp
        if endpoint == "/list_projects":
            return json.dumps(worker_projects[url]), 200
        if endpoint == "/get_project_info":
            name = worker_state[url]
            return json.dumps({"data": {"has_project": name is not None, "project_name": name or ""}}), 200
        if endpoint == "/open_project":
            path = json_data["path"]
            visible = {item["path"]: item["name"] for item in worker_projects[url]}
            if path not in visible:
                return json.dumps({"data": {"error": f"not visible on {url}"}}), 200
            worker_state[url] = visible[path]
            return json.dumps({"data": {"success": True, "project": worker_state[url]}}), 200
        raise AssertionError(f"unexpected request: {method} {endpoint}")

    with patch.object(project_sessions.transport, "do_request", side_effect=do_request):
        listed = project_sessions.list_projects()
        by_name = {item["name"]: item for item in listed["projects"]}

        assert set(by_name) == {"alpha", "beta"}
        lease = project_sessions.checkout(by_name["beta"]["project_id"])
        try:
            assert lease.worker_url == "http://127.0.0.1:8090"
            assert worker_state["http://127.0.0.1:8089"] is None
            assert worker_state["http://127.0.0.1:8090"] == "beta"
        finally:
            project_sessions.release_lease(lease)


def test_checkout_falls_back_when_one_visible_worker_cannot_open_project():
    worker_state = {
        "http://127.0.0.1:8089": None,
        "http://127.0.0.1:8090": None,
    }

    def do_request(
        method,
        endpoint,
        params=None,
        json_data=None,
        timeout=30,
        connection=None,
    ):
        url = connection.active_tcp
        if endpoint == "/list_projects":
            return json.dumps([PROJECTS[0]]), 200
        if endpoint == "/get_project_info":
            name = worker_state[url]
            return json.dumps({"data": {"has_project": name is not None, "project_name": name or ""}}), 200
        if endpoint == "/open_project":
            if url == "http://127.0.0.1:8089":
                return json.dumps({"data": {"error": "project storage is stale"}}), 200
            worker_state[url] = "alpha"
            return json.dumps({"data": {"success": True, "project": "alpha"}}), 200
        raise AssertionError(f"unexpected request: {method} {endpoint}")

    with patch.object(project_sessions.transport, "do_request", side_effect=do_request):
        project_id = project_sessions.list_projects()["projects"][0]["project_id"]
        lease = project_sessions.checkout(project_id)
        try:
            assert lease.worker_url == "http://127.0.0.1:8090"
            assert worker_state["http://127.0.0.1:8090"] == "alpha"
        finally:
            project_sessions.release_lease(lease)


@pytest.mark.asyncio
async def test_clear_worker_queue_cancels_waiters_but_preserves_running_operation(fake_workers):
    ids = _ids()
    first = await project_sessions.acquire_project_operation(ids["alpha"], "first")

    entered = asyncio.Event()

    async def queued_call():
        entered.set()
        lease = await project_sessions.acquire_project_operation(ids["alpha"], "queued")
        try:
            return "ran"
        finally:
            await project_sessions.release_project_operation(lease)

    waiter = asyncio.create_task(queued_call())
    await entered.wait()
    for _ in range(50):
        info = project_sessions.session_info(ids["alpha"])
        if info["queued"] == 1:
            break
        await asyncio.sleep(0.01)
    else:
        raise AssertionError("queued operation did not enter worker queue")

    result = await worker_control.clear_worker_queue(0)

    assert result["cancelled_total"] == 1
    assert result["cancelled_queued"] == 1
    assert result["cancelled_running"] == 0
    assert result["in_flight"] == 1
    assert result["running"] is True
    assert result["current_operation"] == "first"
    assert waiter.cancelled()

    await project_sessions.release_project_operation(first)
    info = project_sessions.session_info(ids["alpha"])
    assert info["in_flight"] == 0
    assert info["queued"] == 0
    assert info["running"] is False


@pytest.mark.asyncio
async def test_recover_worker_cancels_running_and_queued_operations(fake_workers, monkeypatch):
    ids = _ids()
    running_started = asyncio.Event()
    hold = asyncio.Event()

    async def running_call():
        lease = await project_sessions.acquire_project_operation(ids["alpha"], "stuck")
        running_started.set()
        try:
            await hold.wait()
        finally:
            await project_sessions.release_project_operation(lease)

    async def queued_call():
        lease = await project_sessions.acquire_project_operation(ids["alpha"], "queued")
        try:
            await hold.wait()
        finally:
            await project_sessions.release_project_operation(lease)

    running = asyncio.create_task(running_call())
    await running_started.wait()
    queued = asyncio.create_task(queued_call())
    for _ in range(50):
        info = project_sessions.session_info(ids["alpha"])
        if info["queued"] == 1:
            break
        await asyncio.sleep(0.01)
    else:
        raise AssertionError("queued operation did not enter worker queue")

    exits: list[str] = []
    monkeypatch.setattr(
        worker_control,
        "_request_worker_exit",
        lambda url: (exits.append(url), fake_workers.__setitem__(url, None)),
    )
    monkeypatch.setattr(worker_control, "_worker_healthy", lambda _url: True)

    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(worker_control.asyncio, "sleep", no_sleep)

    result = await worker_control.recover_worker(0, timeout_seconds=2)

    assert result["recovered"] is True
    assert result["cancelled_total"] == 2
    assert result["cancelled_queued"] == 1
    assert result["cancelled_running"] == 1
    assert result["previous_project_id"] == ids["alpha"]
    assert exits == ["http://127.0.0.1:8089"]
    assert running.cancelled()
    assert queued.cancelled()

    listed = project_sessions.list_projects()
    worker = listed["workers"][0]
    assert worker["enabled"] is True
    assert worker["in_flight"] == 0
    assert worker["queued"] == 0
    assert worker["running"] is False
    assert worker["project_id"] is None


def test_disabled_active_worker_refuses_new_project_calls(fake_workers):
    ids = _ids()
    lease = project_sessions.checkout(ids["alpha"])
    project_sessions.release_lease(lease)
    with project_sessions._lock:
        first = list(project_sessions._slots.values())[0]
        first.enabled = False

    with pytest.raises(project_sessions.ProjectBusyError, match="disabled or recovering"):
        project_sessions.checkout(ids["alpha"])
