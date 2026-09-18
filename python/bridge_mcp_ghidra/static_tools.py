"""Static MCP tools that are always available, plus startup auto-connect."""

import asyncio
import json
import os
import threading
import time

from . import discovery
from . import dispatch
from . import project_sessions
from . import registry
from . import state
from . import transport
from .config import STATIC_TOOL_NAMES, logger
from .server import Context, mcp
from .validation import validate_server_url


@mcp.tool(name="list_instances")
async def _list_instances_tool() -> str:
    return await state.run_in_worker(_list_instances_sync)


def list_instances() -> str:
    return _list_instances_sync()



@mcp.tool()
async def list_projects(query: str = "", search_dir: str = "") -> str:
    """List Ghidra projects with stable project_id values for project-scoped calls."""
    try:
        result = await state.run_in_worker(project_sessions.list_projects, query, search_dir)
        return json.dumps(result, indent=2)
    except project_sessions.ProjectSessionError as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
async def open_project(project_id: str) -> str:
    """Ensure that project_id has a dedicated headless worker session."""
    try:
        result = await state.run_in_worker(project_sessions.ensure_session, project_id)
        return json.dumps(result, indent=2)
    except project_sessions.ProjectSessionError as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
async def close_project(project_id: str) -> str:
    """Release and close the dedicated headless worker session for project_id."""
    try:
        result = await state.run_in_worker(
            project_sessions.release_project_session,
            project_id,
            True,
        )
        return json.dumps(result, indent=2)
    except project_sessions.ProjectSessionError as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
async def project_session_info(project_id: str) -> str:
    """Return worker/session state for one project_id without changing routing."""
    try:
        result = await state.run_in_worker(project_sessions.session_info, project_id)
        return json.dumps(result, indent=2)
    except project_sessions.ProjectSessionError as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
async def release_project_session(project_id: str, close_project: bool = True) -> str:
    """Release an idle project session so its worker can be reused."""
    try:
        result = await state.run_in_worker(
            project_sessions.release_project_session,
            project_id,
            close_project,
        )
        return json.dumps(result, indent=2)
    except project_sessions.ProjectSessionError as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
async def create_project(name: str, parent_dir: str = "") -> str:
    """Create a project through an idle worker and return its stable project_id."""
    try:
        result = await state.run_in_worker(project_sessions.create_project, name, parent_dir)
        return json.dumps(result, indent=2)
    except project_sessions.ProjectSessionError as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
async def delete_project(project_id: str) -> str:
    """Delete a project by stable project_id; refuses while requests are in flight."""
    try:
        result = await state.run_in_worker(project_sessions.delete_project, project_id)
        return json.dumps(result, indent=2)
    except project_sessions.ProjectSessionError as exc:
        return json.dumps({"error": str(exc)})


# A project can hold hundreds of programs; only the open ones are actionable.
MAX_OPEN_PROGRAMS_LISTED = 25


def _summarize_instance(inst: dict) -> dict:
    """Drop an instance's full program roster, keeping a count and the open ones.

    /mcp/instance_info returns EVERY program in the project. Against a real
    project (626 programs, measured 2026-07-24) that made list_instances
    return ~90KB and blow past MCP result limits — the tool failed precisely
    when it was connected to something worth listing. Nothing downstream reads
    the roster: connect_instance matches on project name.

    Entries are dicts ({name, path, open}) from /mcp/instance_info, or bare
    strings from /list_open_programs — where being listed *is* being open.
    """
    programs = inst.get("programs")
    if not isinstance(programs, list):
        return inst

    summary = {k: v for k, v in inst.items() if k != "programs"}
    open_names = [
        (p.get("path") or p.get("name")) if isinstance(p, dict) else p
        for p in programs
        if not isinstance(p, dict) or p.get("open")
    ]
    summary["program_count"] = len(programs)
    summary["open_programs"] = open_names[:MAX_OPEN_PROGRAMS_LISTED]
    if len(open_names) > MAX_OPEN_PROGRAMS_LISTED:
        summary["open_programs_truncated"] = len(open_names) - MAX_OPEN_PROGRAMS_LISTED
    return summary


@mcp.tool()
async def connect_instance(project: str, ctx: Context | None = None) -> str:
    """
    Resolve a project selector and ensure its isolated project session is active.

    This no longer changes process-global routing. The returned project_id must
    be passed to every project-scoped Ghidra tool.
    """
    try:
        record = await state.run_in_worker(project_sessions.find_project, project)
        result = await state.run_in_worker(
            project_sessions.ensure_session,
            record.project_id,
        )
        result["connected"] = True
        result["note"] = (
            "Project session is active. Pass project_id explicitly to every Ghidra tool; "
            "no global current-project route was changed."
        )
        return json.dumps(result, indent=2)
    except project_sessions.ProjectSessionError as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
def list_tool_groups() -> str:
    """
    List all available tool groups with their tool counts and loaded status.

    Returns each category with: tool count, loaded status, and tool names.
    Use load_tool_group(group) to load a group's tools.
    """
    if not state._full_schema:
        return json.dumps({"error": "No instance connected. Use connect_instance() first."})
    groups = registry._get_group_info()
    return json.dumps({"groups": groups, "total_tools": len(state._full_schema)}, indent=2)


@mcp.tool()
async def load_tool_group(group: str, ctx: Context | None = None) -> str:
    """
    Load all tools in a category. Accepts a category name or "all" to load everything.

    Use list_tool_groups() to see available categories.

    Args:
        group: Category name (e.g. "function", "datatype") or "all"
    """
    if not state._full_schema:
        return json.dumps({"error": "No instance connected. Use connect_instance() first."})

    state.remember_tools_changed_context(ctx)

    def _notify_if_changed(result):
        if result:
            state.notify_tools_changed_from_worker()

    if group == "all":
        # Load all unloaded groups
        all_groups = {td.get("category", "unknown") for td in state._full_schema}
        all_loaded = await state.run_in_worker(
            _load_groups_sync,
            sorted(all_groups),
            done_callback=_notify_if_changed,
        )
        return json.dumps(
            {
                "loaded": "all",
                "new_tools": len(all_loaded),
                "new_tool_names": sorted(all_loaded),
                "total_loaded": len(state._dynamic_tool_names),
            }
        )

    loaded_names = await state.run_in_worker(
        registry._load_group,
        group,
        done_callback=_notify_if_changed,
    )
    if not loaded_names:
        available = sorted({td.get("category", "unknown") for td in state._full_schema})
        if group in state._loaded_groups:
            # Already loaded — return the tool names so the agent knows what's callable
            already = sorted(td["name"] for td in state._full_schema if td.get("category") == group)
            return json.dumps(
                {
                    "message": f"Group '{group}' is already loaded.",
                    "tools": already,
                    "loaded_groups": sorted(state._loaded_groups),
                }
            )
        return json.dumps(
            {
                "error": f"No tools found for group '{group}'",
                "available_groups": available,
            }
        )
    return json.dumps(
        {
            "loaded": group,
            "new_tools": len(loaded_names),
            "tools": sorted(loaded_names),
            "total_loaded": len(state._dynamic_tool_names),
            "loaded_groups": sorted(state._loaded_groups),
        }
    )


@mcp.tool()
async def unload_tool_group(group: str, ctx: Context | None = None) -> str:
    """
    Unload all tools in a category. Default groups are protected from unloading.

    Args:
        group: Category name to unload
    """
    if group in state._default_groups:
        return json.dumps(
            {
                "error": f"Cannot unload default group '{group}'",
                "default_groups": sorted(state._default_groups),
            }
        )

    state.remember_tools_changed_context(ctx)

    removed = await state.run_in_worker(
        registry._unload_group,
        group,
        done_callback=lambda result: result > 0 and state.notify_tools_changed_from_worker(),
    )
    if removed == 0:
        return json.dumps({"message": f"Group '{group}' is not loaded or has no tools."})
    return json.dumps(
        {
            "unloaded": group,
            "removed_tools": removed,
            "total_loaded": len(state._dynamic_tool_names),
            "loaded_groups": sorted(state._loaded_groups),
        }
    )


@mcp.tool()
async def check_tools(tools: str) -> str:
    """
    Check if specific tools are callable right now. Returns status for each tool:
    "callable", "not_loaded" (exists but group not loaded), or "not_found" (doesn't exist).

    Args:
        tools: Comma-separated tool names, e.g. "rename_symbol,batch_set_comments,analyze_function_completeness"
    """
    tool_names = [t.strip() for t in tools.split(",") if t.strip()]
    if not tool_names:
        return json.dumps({"error": "Provide comma-separated tool names"})

    # Build lookup of all known tools -> their group
    all_known: dict[str, str] = {}
    for td in state._full_schema:
        all_known[td["name"]] = td.get("category", "unknown")

    # With no schema fetched there is nothing to check a name against, and
    # every Ghidra tool would be reported "not_found" — indistinguishable from
    # a tool that genuinely doesn't exist. Say "unknown" and name the fix.
    schema_available = bool(all_known)

    # Check each tool
    results: dict[str, dict] = {}
    for name in tool_names:
        if name in STATIC_TOOL_NAMES:
            results[name] = {"status": "callable", "type": "static"}
        elif not schema_available:
            results[name] = {
                "status": "unknown",
                "reason": "no instance connected — tool schema not loaded",
                "fix": "connect_instance(project)",
            }
        elif name in state._dynamic_tool_names:
            results[name] = {
                "status": "callable",
                "group": all_known.get(name, "unknown"),
            }
        elif name in all_known:
            group = all_known[name]
            results[name] = {
                "status": "not_loaded",
                "group": group,
                "fix": f'load_tool_group("{group}")',
            }
        else:
            results[name] = {"status": "not_found"}

    callable_count = sum(1 for r in results.values() if r["status"] == "callable")
    return json.dumps(
        {
            "results": results,
            "summary": f"{callable_count}/{len(tool_names)} callable",
        }
    )


@mcp.tool()
async def search_tools(query: str, limit: int = 15) -> str:
    """
    Search the full Ghidra tool catalog by keyword — including tools whose group
    is not currently loaded. Use this to discover the right tool without paying
    the context cost of loading all groups (run the bridge with --lazy and search
    on demand). Matches against tool name, description, and category.

    Each result reports whether the tool is callable right now; if not, it
    includes the exact load_tool_group(...) call needed to make it callable.

    Args:
        query: Space-separated keywords, e.g. "rename function" or "xref struct".
        limit: Maximum number of results to return (default 15).
    """
    terms = [t.lower() for t in query.split() if t.strip()]
    if not terms:
        return json.dumps({"error": "Provide one or more search keywords"})

    scored: list[tuple[int, dict]] = []
    for td in state._full_schema:
        name = td.get("name", "")
        category = td.get("category", "unknown")
        desc = td.get("description", "") or ""
        haystack = f"{name} {category} {desc}".lower()
        score = 0
        for term in terms:
            if term in name.lower():
                score += 3  # name hits rank highest
            elif term in haystack:
                score += 1
        if score == 0:
            continue
        loaded = name in state._dynamic_tool_names or name in STATIC_TOOL_NAMES
        result = {
            "name": name,
            "group": category,
            "status": "callable" if loaded else "not_loaded",
            "description": desc[:160],
        }
        if not loaded:
            result["fix"] = f'load_tool_group("{category}")'
        scored.append((score, result))

    scored.sort(key=lambda x: x[0], reverse=True)
    matches = [r for _, r in scored[: max(1, limit)]]
    return json.dumps(
        {
            "query": query,
            "match_count": len(scored),
            "returned": len(matches),
            "matches": matches,
        }
    )


@mcp.tool()
async def import_file(
    project_id: str,
    file_path: str,
    project_folder: str = "/",
    language: str | None = None,
    compiler_spec: str | None = None,
    auto_analyze: bool = True,
    ctx: Context | None = None,
) -> str:
    """
    Import a binary file into the explicitly selected Ghidra project session.

    project_id is mandatory and is obtained from list_projects(). The call is
    pinned to that project's worker for its entire lifetime.
    """
    try:
        lease = await state.run_in_worker(project_sessions.checkout, project_id)
    except project_sessions.ProjectSessionError as exc:
        return json.dumps({"error": str(exc)})

    payload: dict = {
        "file_path": file_path,
        "project_folder": project_folder,
        "auto_analyze": auto_analyze,
    }
    if language:
        payload["language"] = language
    if compiler_spec:
        payload["compiler_spec"] = compiler_spec

    keep_lease_for_poll = False
    try:
        result = await state.run_blocking_ghidra_call(
            dispatch.dispatch_post,
            "/import_file",
            payload,
            connection=lease.snapshot,
        )

        try:
            data = json.loads(result)
        except (json.JSONDecodeError, TypeError):
            return result

        response_data = data.get("data", data) if isinstance(data, dict) else {}
        if response_data.get("analyzing") and ctx is not None:
            keep_lease_for_poll = True
            program_name = response_data.get("name", "unknown")
            session = ctx.request_context.session

            async def _poll_analysis():
                try:
                    await asyncio.sleep(5)
                    for _ in range(360):
                        try:
                            status_text = await state.run_blocking_ghidra_call(
                                dispatch.dispatch_get,
                                "/analysis_status",
                                {"program": program_name},
                                connection=lease.snapshot,
                            )
                            status = json.loads(status_text)
                            status_data = status.get("data", status)
                            if not status_data.get("analyzing", True):
                                fn_count = status_data.get("function_count", "?")
                                await session.send_log_message(
                                    level="info",
                                    data=f"Analysis complete for {program_name}: {fn_count} functions found",
                                )
                                return
                        except Exception as exc:
                            logger.debug(f"Analysis poll error for {program_name}: {exc}")
                        await asyncio.sleep(5)
                finally:
                    await state.run_in_worker(project_sessions.release_lease, lease)

            asyncio.create_task(_poll_analysis())

        return result
    finally:
        if not keep_lease_for_poll:
            await state.run_in_worker(project_sessions.release_lease, lease)



def _auto_connect() -> bool:
    """Try to auto-connect to a single running instance on startup.

    Returns True only if dynamic tools were actually registered from a live
    Ghidra. Callers use that to decide whether to keep retrying in the
    background — see `_start_auto_connect_retry`.
    """
    # Try UDS first
    instances = discovery.discover_instances()
    if len(instances) == 1:
        inst = instances[0]
        if transport.uds_supported():
            candidate = state.build_connection_snapshot(
                mode="uds",
                active_socket=inst["socket"],
                connected_project=inst.get("project"),
            )
            logger.info(f"Auto-connecting via UDS to {inst.get('project') or 'unknown'}")
            try:
                schema = registry._fetch_schema(connection=candidate)
                with state._tool_registry_lock:
                    count = registry.register_tools_from_schema(
                        schema,
                        groups=None if not state._lazy_mode else state._default_groups,
                    )
                    state.set_connection_snapshot(
                        "uds",
                        active_socket=inst["socket"],
                        active_tcp=None,
                        connected_project=inst.get("project"),
                    )
                logger.info(f"Auto-registered {count} tools from {inst.get('project') or 'unknown'}")
                return True
            except Exception as e:
                logger.warning(f"UDS auto-connect schema fetch failed: {e}")
        elif inst.get("url") and validate_server_url(inst["url"]):
            # Windows CPython can't dial the discovered socket; discovery
            # enriched it with the instance's TCP url — connect there.
            candidate = state.build_connection_snapshot(
                mode="tcp",
                active_tcp=inst["url"],
                connected_project=inst.get("project"),
            )
            logger.info(
                f"Auto-connecting via TCP ({inst['url']}) to "
                f"{inst.get('project') or 'unknown'} (UDS unavailable on this Python)"
            )
            try:
                schema = registry._fetch_schema(connection=candidate)
                with state._tool_registry_lock:
                    count = registry.register_tools_from_schema(
                        schema,
                        groups=None if not state._lazy_mode else state._default_groups,
                    )
                    state.set_connection_snapshot(
                        "tcp",
                        active_socket=None,
                        active_tcp=inst["url"],
                        connected_project=inst.get("project"),
                    )
                logger.info(f"Auto-registered {count} tools from {inst.get('project') or 'unknown'}")
                return True
            except Exception as e:
                logger.warning(f"TCP auto-connect schema fetch failed: {e}")
    elif len(instances) > 1:
        names = ", ".join(i.get("project") or i.get("socket") or "?" for i in instances)
        logger.info(f"Multiple UDS instances found ({len(instances)}: {names}). " "Use connect_instance() to choose.")
        # Do NOT fall through to the TCP fallback — that would silently
        # connect to whichever Ghidra happened to bind 8089 (possibly a
        # third instance entirely) right after telling the user to choose.
        # Stay unconnected until connect_instance() is called explicitly,
        # matching connect_instance's own multi-instance refusal logic.
        return False

    # Try TCP fallback
    tcp_url = os.getenv("GHIDRA_MCP_URL", DEFAULT_TCP_URL)
    if not validate_server_url(tcp_url):
        logger.warning(f"Refusing to auto-connect to non-local URL: {tcp_url}")
        return False
    try:
        candidate = state.build_connection_snapshot(mode="tcp", active_tcp=tcp_url)
        schema = registry._fetch_schema(connection=candidate)
        with state._tool_registry_lock:
            count = registry.register_tools_from_schema(
                schema,
                groups=None if not state._lazy_mode else state._default_groups,
            )
            state.set_connection_snapshot(
                "tcp",
                active_socket=None,
                active_tcp=tcp_url,
                connected_project=None,
            )
        logger.info(f"Auto-connected via TCP to {tcp_url}, registered {count} tools")
        return True
    except Exception:
        if not instances:
            logger.info("No Ghidra instances found. Tools will be registered on connect_instance().")
    return False


# How often the background retry re-attempts auto-connect. One attempt costs
# roughly a single port-scan timeout now that the scan is concurrent, so a
# short interval is cheap.
AUTO_CONNECT_RETRY_INTERVAL_SEC = 15.0


def _start_auto_connect_retry(interval: float = AUTO_CONNECT_RETRY_INTERVAL_SEC) -> threading.Thread:
    """Retry `_auto_connect()` in the background until Ghidra shows up.

    `_auto_connect()` runs exactly once during startup, so a bridge launched
    BEFORE Ghidra registered zero dynamic tools and had no way to notice
    Ghidra arriving afterwards. That is not hypothetical: a bridge started
    2026-08-04 sat beside a Ghidra started 2026-08-06 for four days holding
    only the static tools, which presents to the operator as "the Ghidra MCP
    tools are missing" while Ghidra itself is demonstrably healthy.

    The thread is a daemon and stops permanently on the first success, after
    which it emits tools/list_changed so clients re-fetch the tool list.
    """

    def _loop() -> None:
        while True:
            time.sleep(interval)
            if state._transport_mode != "none":
                # Something else connected us (e.g. an explicit
                # connect_instance call) — nothing left to retry.
                return
            try:
                connected = _auto_connect()
            except Exception as e:  # never let the retry thread die silently
                logger.debug(f"Auto-connect retry attempt failed: {e}")
                continue
            if connected:
                logger.info("Auto-connect retry succeeded — Ghidra tools are now registered")
                try:
                    state.notify_tools_changed_from_worker()
                except Exception as e:
                    logger.debug(f"tools/list_changed notification failed after retry: {e}")
                return

    thread = threading.Thread(target=_loop, name="GhidraMCP-AutoConnectRetry", daemon=True)
    thread.start()
    return thread
