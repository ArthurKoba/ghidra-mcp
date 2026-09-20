from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_score7_cross_objdump_is_built_into_docker_image() -> None:
    dockerfile = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")

    assert "--target=score-elf" in dockerfile
    assert "score-elf-objdump --version" in dockerfile
    assert (
        "COPY --from=score-binutils-builder "
        "/opt/score-binutils/bin/score-elf-objdump "
        "/usr/local/bin/score-elf-objdump"
    ) in dockerfile


def test_score7_ghidra_script_is_external_non_mutating_bridge() -> None:
    script = (
        ROOT / "ghidra_scripts" / "Score7ExternalDisassemble.java"
    ).read_text(encoding="utf-8")

    assert 'OBJDUMP = "/usr/local/bin/score-elf-objdump"' in script
    assert '"-m", "score7"' in script
    assert '"-EL"' in script
    assert '"-EB"' in script
    assert "/artifacts/exports" in script

    # This first-stage integration must not create fake Ghidra instructions,
    # change the program language, or rewrite program bytes.
    forbidden = (
        "setLanguage(",
        "createInstruction",
        "setBytes(",
        "clearListing(",
    )
    assert all(token not in script for token in forbidden)
