from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_compose_separates_artifacts_projects_and_builtin_scripts():
    compose = (ROOT / "docker-compose.yaml").read_text(encoding="utf-8")
    assert 'GHIDRA_MCP_FILE_ROOT: "/artifacts"' in compose
    assert 'GHIDRA_MCP_PROJECT_ROOT: "/projects"' in compose
    assert 'GHIDRA_MCP_SCRIPT_ROOT: "/artifacts/scripts"' in compose
    assert "ghidra-projects:/projects" in compose
    assert "koba-artifacts:/artifacts" in compose
    assert "/home/ubuntu/ghidra_scripts" not in compose
    assert "/home/ghidra/ghidra_scripts" not in compose


def test_image_ships_repo_scripts_and_has_ephemeral_cache():
    dockerfile = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY ghidra_scripts /app/ghidra_scripts" in dockerfile
    assert "/tmp/ghidra-script-cache" in dockerfile
    assert "/artifacts/inbox" in dockerfile
