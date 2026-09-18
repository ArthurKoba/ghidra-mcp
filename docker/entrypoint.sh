#!/bin/bash
# GhidraMCP Headless Server Entrypoint Script

set -e

# Configuration from environment variables
PORT=${GHIDRA_MCP_PORT:-8089}
BIND_ADDRESS=${GHIDRA_MCP_BIND_ADDRESS:-"0.0.0.0"}  # Default to all interfaces for Docker
JAVA_OPTS=${JAVA_OPTS:-"-Xmx4g -XX:+UseG1GC"}
GHIDRA_USER=${GHIDRA_USER:-""}  # Set to project owner name to bypass ownership checks

# Shared Ghidra server configuration
GHIDRA_SERVER_HOST=${GHIDRA_SERVER_HOST:-""}
GHIDRA_SERVER_PORT=${GHIDRA_SERVER_PORT:-""}
GHIDRA_SERVER_USER=${GHIDRA_SERVER_USER:-""}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  GhidraMCP Headless Server${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Print configuration
echo -e "${YELLOW}Configuration:${NC}"
echo "  Bind Address: ${BIND_ADDRESS}"
echo "  Port: ${PORT}"
echo "  Java Options: ${JAVA_OPTS}"
echo "  Ghidra Home: ${GHIDRA_HOME}"
if [ -n "${GHIDRA_USER}" ]; then
    echo "  Ghidra User: ${GHIDRA_USER}"
fi
if [ -n "${GHIDRA_SERVER_HOST}" ]; then
    echo "  Server Host: ${GHIDRA_SERVER_HOST}"
    echo "  Server Port: ${GHIDRA_SERVER_PORT:-13100}"
fi
if [ -n "${GHIDRA_SERVER_USER}" ]; then
    echo "  Server User: ${GHIDRA_SERVER_USER}"
fi
echo ""

# Check Ghidra installation
if [ ! -d "${GHIDRA_HOME}" ]; then
    echo -e "${RED}Error: Ghidra not found at ${GHIDRA_HOME}${NC}"
    exit 1
fi

# Build classpath with Ghidra JARs
CLASSPATH="/app/GhidraMCP.jar"

# Add Ghidra Framework JARs
for jar in ${GHIDRA_HOME}/Ghidra/Framework/*/lib/*.jar; do
    CLASSPATH="${CLASSPATH}:${jar}"
done

# Add Ghidra Feature JARs
for jar in ${GHIDRA_HOME}/Ghidra/Features/*/lib/*.jar; do
    CLASSPATH="${CLASSPATH}:${jar}"
done

# Add Ghidra Processor JARs
for jar in ${GHIDRA_HOME}/Ghidra/Processors/*/lib/*.jar; do
    CLASSPATH="${CLASSPATH}:${jar}"
done

# Add application lib JARs
if [ -d "/app/lib" ]; then
    for jar in /app/lib/*.jar; do
        [ -f "$jar" ] && CLASSPATH="${CLASSPATH}:${jar}"
    done
fi

# Worker pool configuration
WORKER_COUNT=${GHIDRA_MCP_WORKER_COUNT:-1}
WORKER_JAVA_OPTS=${GHIDRA_MCP_WORKER_JAVA_OPTS:-${JAVA_OPTS}}

if ! [[ "${WORKER_COUNT}" =~ ^[1-9][0-9]*$ ]]; then
    echo -e "${RED}Error: GHIDRA_MCP_WORKER_COUNT must be a positive integer${NC}"
    exit 1
fi

# Build user.name option if GHIDRA_USER is set
USER_OPT=""
if [ -n "${GHIDRA_USER}" ]; then
    USER_OPT="-Duser.name=${GHIDRA_USER}"
fi

EXTRA_ARGS=()
if [ "$#" -gt 0 ]; then
    EXTRA_ARGS=("$@")
fi
if [ -n "${PROGRAM_FILE:-}" ] && [ -f "${PROGRAM_FILE}" ]; then
    EXTRA_ARGS+=("--file" "${PROGRAM_FILE}")
fi
if [ -n "${PROJECT_PATH:-}" ] && [ -e "${PROJECT_PATH}" ]; then
    if [ "${WORKER_COUNT}" -gt 1 ]; then
        echo -e "${RED}Error: PROJECT_PATH is incompatible with a multi-worker pool; use project_id routing instead.${NC}"
        exit 1
    fi
    EXTRA_ARGS+=("--project" "${PROJECT_PATH}")
fi

echo -e "${YELLOW}Worker pool:${NC}"
echo "  Workers: ${WORKER_COUNT}"
echo "  Base Port: ${PORT}"
echo "  Worker Java Options: ${WORKER_JAVA_OPTS}"
echo ""

start_worker() {
    local index="$1"
    local worker_port=$((PORT + index))
    local worker_home="/data/workers/worker-${index}/home"
    local worker_cache="/tmp/ghidra-script-cache/worker-${index}"

    mkdir -p "${worker_home}" "${worker_cache}"

    echo -e "${GREEN}Starting worker ${index} on port ${worker_port}...${NC}"
    HOME="${worker_home}" \
    GHIDRA_MCP_SCRIPT_CACHE="${worker_cache}" \
    java \
        ${WORKER_JAVA_OPTS} \
        ${USER_OPT} \
        -Duser.home="${worker_home}" \
        -Dghidra.home="${GHIDRA_HOME}" \
        -Dapplication.name="GhidraMCP-worker-${index}" \
        -classpath "${CLASSPATH}" \
        com.xebyte.headless.GhidraMCPHeadlessServer \
        --port "${worker_port}" \
        --bind "${BIND_ADDRESS}" \
        "${EXTRA_ARGS[@]}" &
    PIDS+=("$!")
}

if [ "${WORKER_COUNT}" -eq 1 ]; then
    worker_home="/data/workers/worker-0/home"
    worker_cache="/tmp/ghidra-script-cache/worker-0"
    mkdir -p "${worker_home}" "${worker_cache}"
    echo -e "${GREEN}Starting single Ghidra worker...${NC}"
    exec env HOME="${worker_home}" GHIDRA_MCP_SCRIPT_CACHE="${worker_cache}" \
        java \
        ${WORKER_JAVA_OPTS} \
        ${USER_OPT} \
        -Duser.home="${worker_home}" \
        -Dghidra.home="${GHIDRA_HOME}" \
        -Dapplication.name="GhidraMCP-worker-0" \
        -classpath "${CLASSPATH}" \
        com.xebyte.headless.GhidraMCPHeadlessServer \
        --port "${PORT}" \
        --bind "${BIND_ADDRESS}" \
        "${EXTRA_ARGS[@]}"
fi

PIDS=()

cleanup() {
    trap - SIGTERM SIGINT
    echo ""
    echo -e "${YELLOW}Shutting down GhidraMCP worker pool...${NC}"
    if [ "${#PIDS[@]}" -gt 0 ]; then
        kill "${PIDS[@]}" 2>/dev/null || true
        wait "${PIDS[@]}" 2>/dev/null || true
    fi
}

trap cleanup SIGTERM SIGINT EXIT

for ((i=0; i<WORKER_COUNT; i++)); do
    start_worker "${i}"
done

# A worker exit means the pool is no longer consistent. Terminate the rest and
# let Docker restart the whole service instead of silently running degraded.
set +e
wait -n "${PIDS[@]}"
STATUS=$?
set -e
if [ "${STATUS}" -eq 0 ]; then
    STATUS=1
fi
echo -e "${RED}A Ghidra worker exited (status ${STATUS}); restarting the pool.${NC}"
exit "${STATUS}"
