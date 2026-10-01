# AGENTS.md — ghidra-mcp Project

You are a coding agent working on **ghidra-mcp**, a Model Context Protocol server that bridges Ghidra's reverse engineering capabilities with AI tools.

## Project Context

- **Repo**: https://github.com/bethington/ghidra-mcp
- **Version**: 7.0.0
- **Language**: Java (Ghidra extension) + Python (MCP bridge)
- **Key feature**: 267 for binary analysis, knowledge database, BSim integration, headless server support, AI documentation workflows

## Directory Structure

- `src/` — Java source for Ghidra extension and headless server
- `python/bridge_mcp_ghidra/` — Python MCP bridge package (`bridge-mcp-ghidra` console script / `python -m bridge_mcp_ghidra`)
- `pyproject.toml` + `uv.lock` — uv project (ships the `ghidra-mcp-bridge` wheel; deps via PEP 735 groups)
- `docs/` — Documentation and workflow prompts
- `tests/` — Python unit tests and endpoint catalog
- `CHANGELOG.md` — Version history

## Current Priorities

1. Maintain headless server parity with GUI plugin endpoints
2. Keep `tests/endpoints.json` in sync with Java endpoint registrations
3. Maintain CI/CD pipeline health
4. Community PR reviews

## Guidelines

- Run tests before committing: `pytest tests/unit/ -v --no-cov`
- Build: `mvn clean package assembly:single -DskipTests`
- Quick compile check: `mvn clean compile -q`
- Follow existing code style
- Update CHANGELOG.md for user-facing changes
- Create PRs for review (don't push directly to main)
- Use `python -m tools.setup bump-version --new X.Y.Z` to bump version across all maintained files atomically

## Commands

- Build: `mvn clean package assembly:single -DskipTests`
- Quick compile: `mvn clean compile -q`
- Test (Python): `pytest tests/unit/ -v --no-cov`
- Preflight: `python -m tools.setup preflight --ghidra-path F:\ghidra_12.1.2_PUBLIC`
- Deploy: `python -m tools.setup ensure-prereqs --ghidra-path F:\ghidra_12.1.2_PUBLIC` then `python -m tools.setup build` then `python -m tools.setup deploy --ghidra-path F:\ghidra_12.1.2_PUBLIC`
- Version bump: `python -m tools.setup bump-version --new X.Y.Z`

## Project-session lifecycle

Headless project routing separates persistent project state from session-local open-program handles.

- A project being present and healthy does **not** mean any program is currently open in its worker session.
- Idle project sessions may be auto-released. The default timeout is 900 seconds unless deployment settings override it. Releasing a session closes the worker's open-program handles; it does not delete the project or its saved analysis.
- If an operation returns `Program not found` or `No program loaded`, do not infer project corruption. First inspect the project session, list project files, and reopen the required program with `load_program_from_project` / `open_program` using its project path.
- If the project session itself is not active, reacquire/open the project first; the router will assign an eligible idle worker.
- Only treat a program as missing or damaged after confirming that its project file is absent or fails to open with a concrete backend diagnostic.
- Worker count is capacity, not project ownership. A worker may serve a project session and later be reused after release. Do not assume one permanent worker per repository/project unless an explicit affinity feature is added.
- Prefer explicit recovery guidance over hidden auto-open behavior. Automatic program reopen may be added as a convenience, but it must preserve unambiguous project-path selection and must not hide real open/import failures.

