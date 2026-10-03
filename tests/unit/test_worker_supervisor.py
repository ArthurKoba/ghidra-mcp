from pathlib import Path


def test_multi_worker_entrypoint_restarts_only_exited_worker() -> None:
    text = Path("docker/entrypoint.sh").read_text(encoding="utf-8")

    assert 'PIDS["${index}"]="$!"' in text
    assert 'wait -n -p EXITED_PID "${PIDS[@]}"' in text
    assert 'start_worker "${EXITED_INDEX}"' in text
    assert "restarting only that worker" in text
    assert "restarting the pool" not in text
