"""Source assembly and linking, with independent output validation."""
import hashlib
import json
import subprocess
import struct
from pathlib import Path

from ._contracts import BuildResult, MemoryLayout, SdkError, Toolchain
from ._elf import linked_segments
from ._symbols import embed_link_map


def build_image(sources: tuple[Path, ...], output: Path, toolchain: Toolchain,
                layout: MemoryLayout = MemoryLayout(), *, entry_word: int | None = None) -> BuildResult:
    layout.validate()
    if entry_word is not None and not layout.pm_start <= entry_word <= layout.pm_end:
        raise SdkError(f"Explicit PM entry is outside layout: {entry_word:#x}")
    if not sources or len(sources) > 128:
        raise SdkError("Supply between 1 and 128 DSP assembly sources")
    source_paths = tuple(source.resolve() for source in sources)
    if any(not path.is_file() or path.suffix.lower() != ".dsp" for path in source_paths):
        raise SdkError("Every input must be an existing .dsp source")
    assembler, linker = toolchain.executable("as218x"), toolchain.executable("ld21")
    output = output.resolve()
    if output.exists():
        raise SdkError(f"Refusing to overwrite build directory: {output}")
    output.mkdir(parents=True)
    logs = output / "build.log"

    def run(command: list[str]) -> None:
        try:
            result = subprocess.run(command, cwd=output, capture_output=True, text=True,
                                    timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SdkError(f"Tool invocation failed: {Path(command[0]).name}: {exc}") from exc
        with logs.open("a", encoding="utf-8") as log:
            log.write(json.dumps(command) + "\n" + result.stdout + result.stderr)
        if result.returncode:
            raise SdkError(f"{Path(command[0]).name} exited {result.returncode}; see {logs}")

    objects = []
    for index, source in enumerate(source_paths):
        obj = output / f"source-{index:03d}.o"
        run([str(assembler), "-2", "181", "-o", str(obj), str(source)])
        objects.append(obj)
    ldf = output / "layout.ldf"
    ldf.write_text(f"""ARCHITECTURE(ADSP-2181)
MEMORY {{
  code {{ TYPE(PM RAM) START({layout.pm_start:#x}) END({layout.pm_end:#x}) WIDTH(24) }}
  data {{ TYPE(DM RAM) START({layout.dm_start:#x}) END({layout.dm_end:#x}) WIDTH(16) }}
}}
PROCESSOR p0 {{
  OUTPUT($COMMAND_LINE_OUTPUT_FILE)
  SECTIONS {{
    int_pm {{ INPUT_SECTIONS($COMMAND_LINE_OBJECTS(program0))
              INPUT_SECTIONS($COMMAND_LINE_OBJECTS(pmdata0)) }} > code
    int_dm {{ INPUT_SECTIONS($COMMAND_LINE_OBJECTS(data0)) }} > data
  }}
}}
""", encoding="utf-8")
    elf = output / "image.elf"
    map_path = output / "image.map"
    run([str(linker), "-L", "-m", str(map_path), "-o", str(elf), "-T", str(ldf), *(str(path) for path in objects)])
    segments = linked_segments(elf)
    symbols = embed_link_map(elf, map_path, segments)
    if linked_segments(elf) != segments:
        raise SdkError("Symbol metadata changed the initialized image")
    if entry_word is not None:
        if not any(segment.space == "PM" and segment.word_address <= entry_word <
                   segment.word_address + segment.word_count for segment in segments):
            raise SdkError("Explicit PM entry is outside initialized PM")
        # ld21 leaves e_entry at zero. Set only this metadata field in our new
        # generated ELF when explicitly requested, never in a stock image.
        raw = bytearray(elf.read_bytes())
        struct.pack_into("<I" if raw[5] == 1 else ">I", raw, 24, entry_word)
        elf.write_bytes(raw)
        if linked_segments(elf) != segments:
            raise SdkError("Entry-point metadata update changed the load segments")
    for segment in segments:
        start, end = (layout.pm_start, layout.pm_end) if segment.space == "PM" else (layout.dm_start, layout.dm_end)
        if not start <= segment.word_address or segment.word_address + segment.word_count > end + 1:
            raise SdkError(f"Linked {segment.space} segment exceeds the requested memory layout")
        (output / f"{segment.space.lower()}.bin").write_bytes(segment.data)
    manifest = {
        "schema": 1, "state": "ASSEMBLED_AND_LINKED_NOT_HARDWARE_ACCEPTED",
        "profile": "adsp218x-d16-candidate", "instruction_word_bytes": 3,
        "explicit_entry_word": entry_word,
        "dm_word_bytes": 2, "word_byte_order": "big",
        "warning": "This is a DSP image, not a flashable SPHE firmware. No startup/ABI/hardware acceptance is implied.",
        "symbol_count": len(symbols),
        "symbol_address_units": "DSP words",
        "elf_sha256": hashlib.sha256(elf.read_bytes()).hexdigest(),
        "sources": [{"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in source_paths],
        "tools": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (assembler, linker)},
        "segments": [{"space": segment.space, "word_address": segment.word_address,
                      "word_bytes": segment.word_bytes, "word_count": segment.word_count,
                      "file": segment.space.lower() + ".bin",
                      "sha256": hashlib.sha256(segment.data).hexdigest()} for segment in segments],
    }
    manifest_path = output / "image.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return BuildResult(elf, manifest_path, segments)
