from pathlib import Path


def test_multi_worker_entrypoint_restarts_only_exited_worker() -> None:
    text = Path("docker/entrypoint.sh").read_text(encoding="utf-8")

    assert 'PIDS["${index}"]="$!"' in text
    assert 'wait -n -p EXITED_PID "${PIDS[@]}"' in text
    assert 'start_worker "${EXITED_INDEX}"' in text
    assert "restarting only that worker" in text
    assert "restarting the pool" not in text


def test_worker_supervisor_exposes_shared_fast_restart_fifo() -> None:
    text = Path("docker/entrypoint.sh").read_text(encoding="utf-8")

    assert "worker-control.fifo" in text
    assert "mkfifo" in text
    assert 'kill -KILL "${pid}"' in text
    restart_block = text.split("restarting only that worker", 1)[1].split("done", 1)[0]
    assert "sleep 1" not in restart_block
