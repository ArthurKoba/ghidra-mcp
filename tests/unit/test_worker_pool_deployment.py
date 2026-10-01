from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "docker-compose.yaml").read_text(encoding="utf-8")
DOCKERFILE = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")


def _quoted_env(name: str) -> str:
    match = re.search(rf'{re.escape(name)}:\s*"([^"]+)"', COMPOSE)
    assert match, f"{name} missing from docker-compose.yaml"
    return match.group(1)


def test_worker_pool_urls_match_worker_count_and_exposed_ports() -> None:
    count = int(_quoted_env("GHIDRA_MCP_WORKER_COUNT"))
    urls = [item.strip() for item in _quoted_env("GHIDRA_MCP_WORKER_URLS").split(",")]

    assert count == 5
    assert len(urls) == count

    ports = [int(url.rsplit(":", 1)[1]) for url in urls]
    assert ports == list(range(8089, 8089 + count))

    expose = re.search(r"^EXPOSE\s+(.+)$", DOCKERFILE, re.MULTILINE)
    assert expose
    exposed_ports = {int(item) for item in expose.group(1).split()}
    assert set(ports).issubset(exposed_ports)


def test_worker_heap_budget_stays_below_container_limit() -> None:
    count = int(_quoted_env("GHIDRA_MCP_WORKER_COUNT"))
    opts = _quoted_env("GHIDRA_MCP_WORKER_JAVA_OPTS")
    heap = re.search(r"-Xmx(\d+)m", opts)
    limit = re.search(r"^\s*mem_limit:\s*(\d+)g\s*$", COMPOSE, re.MULTILINE)

    assert heap
    assert limit

    total_heap_mib = count * int(heap.group(1))
    container_limit_mib = int(limit.group(1)) * 1024

    # Leave native/JVM/Ghidra overhead outside the configured maximum heaps.
    assert total_heap_mib <= container_limit_mib * 0.80
