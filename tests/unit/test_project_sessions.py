import json
from unittest.mock import patch

import pytest

from bridge_mcp_ghidra import project_sessions


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
            return json.dumps(
                {
                    "data": {
                        "has_project": name is not None,
                        "project_name": name or "",
                    }
                }
            ), 200
        if endpoint == "/open_project":
            path = json_data["path"]
            state[url] = by_path[path]
            return json.dumps(
                {"data": {"success": True, "project": state[url]}}
            ), 200
        if endpoint == "/close_project":
            closed = state[url]
            state[url] = None
            return json.dumps(
                {"data": {"success": True, "closed": closed}}
            ), 200
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
        with pytest.raises(project_sessions.ProjectBusyError, match="in-flight"):
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
