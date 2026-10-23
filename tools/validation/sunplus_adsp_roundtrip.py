"""Compare Analyzer-rendered DSP instructions with independent ADSP assemblers.

This is a syntax adapter and byte comparator, NOT an instruction decoder.
It never uses expected machine bits to synthesize source or inserts .word/.byte.
Only entries explicitly present in the input Analyzer listing are counted.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
from typing import Any

ADAPTER_VERSION = "1"


@dataclass(frozen=True)
class AssemblyResult:
    state: str
    machine_hex: str
    diagnostics: str
    source: str


def normalize(text: str, dialect: str = "reference") -> str:
    """Translate only notation, retaining all displayed operands and modes."""
    if dialect not in ("reference", "sdk"):
        raise ValueError("Unknown assembler dialect")
    if not text.strip() or re.search(r"[\n\r;#{}]", text):
        raise ValueError("Empty or non-instruction source")
    # Empty-leading mnemonic is the existing SLEIGH register-move rendering.
    # Preserve that distinction: an ALU PASS updates flags; a register move does not.
    compute_assignment = bool(re.match(r"^(?:IF [A-Z_ ]+ )?(?:AR|AF|NONE)\s*=", text))
    source = re.sub(r"\s+", " ", text.strip()).lower()
    # These mnemonic aliases are defined in the existing Sunplus SLEIGH source.
    if source.startswith("ldi "):
        target, value = source[4:].split(",", 1)
        source = f"{target.strip()} = {value.strip()}"
    elif source.startswith(("dmread ", "dmwrite ", "ioread ", "iowrite ")):
        operation, args = source.split(" ", 1)
        operands = [x.strip() for x in args.split(",")]
        space = "io" if operation.startswith("io") else "dm"
        if operation.endswith("read"):
            if len(operands) not in (2, 3):
                raise ValueError("Invalid read operand count")
            source = f"{operands[0]} = {space}({','.join(operands[1:])})"
        else:
            if len(operands) not in (2, 3):
                raise ValueError("Invalid write operand count")
            source = f"{space}({','.join(operands[:-1])}) = {operands[-1]}"
    source = re.sub(r"\b(ena|dis)_([a-z_]+)\b", r"\1 \2", source)
    source = re.sub(r"\bjump_resident_([0-9a-f]{4})\b", r"jump 0x\1", source)
    if source == "sat_mr":
        source = "if mv sat mr"
    if source.startswith("exp(hi) "):
        source = "se = exp " + source[len("exp(hi) "):] + " (hi)"
    # Existing pure Type-9 amf5=4 constructor omits the explicit SS suffix.
    if re.fullmatch(r"mr\s*=\s*\w+\s*\*\s*\w+", source):
        source += " (ss)"
    # The vendor grammar spells an ALU add of literal zero as PASS, not an
    # immediate ALU constant. This applies to the compute side of parallel ops.
    source = re.sub(r"\b(ar|af|none)\s*=\s*(\w+)\s*\+\s*(?:0|0x0)(?=\s*(?:,|$))", r"\1 = pass \2", source)
    if compute_assignment:
        # Only transform the arithmetic component, not parallel data-register moves.
        depth = 0
        boundary = len(source)
        for i, char in enumerate(source):
            depth += (char == "(") - (char == ")")
            if char == "," and depth == 0:
                boundary = i
                break
        compute, parallel = source[:boundary].strip(), source[boundary:]
        left, right = compute.split("=", 1)
        right = right.strip()
        number = r"(?:0x[0-9a-f]+|[0-9]+)"
        if re.fullmatch(r"(?:ay[01]|af|" + number + r")", right):
            right = "pass " + right
        elif re.fullmatch(number + r"\s*[+-]\s*" + number, right):
            selected = re.fullmatch(r"(" + number + r")\s*([+-])\s*1", right)
            if dialect == "sdk" and selected and int(selected.group(1), 0) != 0:
                operation = "inc_const" if selected.group(2) == "+" else "dec_const"
                right = operation + "(" + selected.group(1) + ")"
            else:
                right = "pass (" + right + ")"
        else:
            right = re.sub(r"^(?:0|0x0)\s*-\s*([a-z][a-z0-9]*)$", r"-\1", right)
        if dialect == "sdk":
            # Vendor spelling of constant-minus-X. It retains the operation;
            # no machine-word value participates in this transformation.
            reverse = re.fullmatch(r"(" + number + r")\s*-\s*([a-z][a-z0-9]*)", right)
            if reverse:
                right = "-" + reverse.group(2) + " + " + reverse.group(1)
        if dialect == "sdk" and left.strip() == "ar" and re.fullmatch(r",\s*ar\s*=\s*ar", parallel):
            # Read-first parallel self-move discards the ALU result, retaining
            # flags. The vendor NONE syntax encodes exactly this operation.
            left, parallel = "none", ""
        source = left.rstrip() + " = " + right + parallel
    # These are named MAC clear/transfer aliases in both vendor grammars.
    # Restrict to displayed MX0*0; other operand encodings remain unmodified.
    source = re.sub(r"^(mr|mf)\s*=\s*mx0\s*\*\s*0\s*\(ss\)", r"\1 = 0", source)
    source = re.sub(r"^(mr|mf)\s*=\s*mr\s*\+\s*mx0\s*\*\s*0\s*\(ss\)", r"\1 = mr", source)
    source = re.sub(r"^(mr|mf)\s*=\s*mr\s*\+\s*mx0\s*\*\s*0\s*\(rnd\)", r"\1 = mr (rnd)", source)
    return source + ";"


def elf_section(path: Path, wanted: str) -> tuple[bytes, int]:
    raw = path.read_bytes()
    if len(raw) < 52 or raw[:5] != b"\x7fELF\x01" or raw[5] not in (1, 2):
        raise ValueError("Expected ELF32 object")
    endian = "<" if raw[5] == 1 else ">"
    header = struct.unpack_from(endian + "HHIIIIIHHHHHH", raw, 16)
    offset, width, count, strindex = header[5], header[10], header[11], header[12]
    if width < 40 or offset + width * count > len(raw) or not 0 <= strindex < count:
        raise ValueError("Invalid ELF section directory")
    sections = [struct.unpack_from(endian + "IIIIIIIIII", raw, offset + i * width) for i in range(count)]
    names_header = sections[strindex]
    names = raw[names_header[4]:names_header[4] + names_header[5]]
    hits = []
    for section in sections:
        name = names[section[0]:].split(b"\0", 1)[0].decode("ascii", errors="strict")
        if name == wanted:
            if section[4] + section[5] > len(raw):
                raise ValueError("ELF section extends past end of file")
            hits.append((raw[section[4]:section[4] + section[5]], section[3]))
    if len(hits) != 1:
        raise ValueError(f"Expected exactly one {wanted} section; found {len(hits)}")
    return hits[0]


def execute(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=5, check=False)


@lru_cache(maxsize=8)
def tool_fingerprint(path: Path, size: int, mtime_ns: int) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assemble(source: str, tool: str, executable: Path, linker: Path, cache: Path) -> AssemblyResult:
    info = executable.stat()
    fingerprint = tool_fingerprint(executable, info.st_size, info.st_mtime_ns)
    if tool != "as2181":
        link_info = linker.stat()
        fingerprint += tool_fingerprint(linker, link_info.st_size, link_info.st_mtime_ns)
    key = hashlib.sha256((ADAPTER_VERSION + tool + fingerprint + source).encode()).hexdigest()
    work = cache / tool / key
    record = work / "result.json"
    if record.is_file():
        result = AssemblyResult(**json.loads(record.read_text()))
        if result.source != source:
            raise ValueError("Cache source mismatch")
        if result.state != "TOOL_ERROR":
            return result
        # Prior workspace/path/timeouts may have produced transient TOOL_ERROR.
        # Infrastructure failures are not a compiler or ISA verdict and must
        # never become permanent cache entries.
        record.unlink()
    work.mkdir(parents=True, exist_ok=True)
    input_file = work / "instruction.dsp"
    try:
        if tool == "as2181":
            input_file.write_text(".module/ram/abs=h#0 corpus;\n" + source + "\n.endmod;\n")
            output = work / "instruction.exe"
            run = execute([str(executable), "-o", str(output), str(input_file)], work)
            diagnostic = (run.stdout + run.stderr).replace(str(work), "<case>")
            if run.returncode:
                result = AssemblyResult("ASSEMBLER_REJECTED", "", diagnostic, source)
            else:
                values = re.findall(rb"(?m)^[0-9A-F]{6}\r?$", output.read_bytes())
                machine = b"".join(bytes.fromhex(x.decode().strip()) for x in values)
                result = AssemblyResult("ENCODED" if len(machine) == 3 else "NON_SINGLE_WORD", machine.hex(), diagnostic, source)
        else:
            input_file.write_text(".section/pm program0;\n" + source + "\n")
            obj, output, ldf = work / "instruction.o", work / "instruction.elf", work / "instruction.ldf"
            ldf.write_text("ARCHITECTURE(ADSP-2181)\nMEMORY { code { TYPE(PM RAM) START(0x0000) END(0x3fff) WIDTH(24) } }\nPROCESSOR p0 { OUTPUT($COMMAND_LINE_OUTPUT_FILE) SECTIONS { int_pm { INPUT_SECTIONS($COMMAND_LINE_OBJECTS(program0)) } > code } }\n")
            run = execute([str(executable), "-2", "181", "-o", str(obj), str(input_file)], work)
            diagnostic = (run.stdout + run.stderr).replace(str(work), "<case>")
            if run.returncode:
                result = AssemblyResult("ASSEMBLER_REJECTED", "", diagnostic, source)
            else:
                link = execute([str(linker), "-o", str(output), "-T", str(ldf), str(obj)], work)
                diagnostic += (link.stdout + link.stderr).replace(str(work), "<case>")
                if link.returncode:
                    result = AssemblyResult("LINKER_REJECTED", "", diagnostic, source)
                else:
                    machine, address = elf_section(output, "int_pm")
                    if address != 0:
                        raise ValueError("Link address does not match the test LDF")
                    result = AssemblyResult("ENCODED" if len(machine) == 3 else "NON_SINGLE_WORD", machine.hex(), diagnostic, source)
    except (subprocess.TimeoutExpired, ValueError, OSError) as exc:
        result = AssemblyResult("TOOL_ERROR", "", str(exc), source)
    # Cache deterministic assembler/linker responses only. A transient
    # OSError/timeout must be retriable with a corrected environment.
    if result.state != "TOOL_ERROR":
        with record.open("x") as f:
            json.dump(asdict(result), f, ensure_ascii=False, indent=2)
    return result


def checked_listing(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text())
    # Earlier Analyzer listing exports used version/path/native_functions,
    # while current saved MCP exports use saved_version/program_path/native_total.
    # Normalize only metadata, reject conflicting aliases and retain all bytes.
    for primary, alternate in (("version", "saved_version"),
                               ("path", "program_path"),
                               ("native_functions", "native_total")):
        if primary in data and alternate in data and data[primary] != data[alternate]:
            raise ValueError("Contradictory Analyzer evidence fields: " + primary)
        if primary not in data:
            data[primary] = data[alternate]
    rows = data["instructions"]
    if data["decoded_instructions"] != len(rows) or len(rows) != len({r["address"] for r in rows}):
        raise ValueError("Instruction denominator or unique-address count differs")
    for row in rows:
        if not re.fullmatch(r"[0-9a-f]{6}", row["bytes"]) or not row["address"].startswith("PM:"):
            raise ValueError("Malformed native instruction evidence")
        if int(row["address"].split(":", 1)[1], 16) != row["word_address"]:
            raise ValueError("PM word address mismatch")
    return data


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--corpus", type=Path, required=True)
    p.add_argument("--tool-root", type=Path)
    p.add_argument("--sdk-root", type=Path, help="Use the candidate SDK instead of the two unchanged reference assemblers")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--cache", type=Path, required=True)
    p.add_argument("--workers", type=int, default=2)
    args = p.parse_args()
    if not 1 <= args.workers <= 4:
        p.error("--workers must be 1..4")
    if bool(args.tool_root) == bool(args.sdk_root):
        p.error("Supply exactly one of --tool-root or --sdk-root")
    dialect = "sdk" if args.sdk_root else "reference"
    root = (args.sdk_root or args.tool_root).resolve()
    tools = {"sdk-as218x": root / "bin/as218x"} if args.sdk_root else {
        "as2181": root / "as2181/as2181", "as218x": root / "open21xx/as21/as218x"}
    linker = root / ("bin/ld21" if args.sdk_root else "open21xx/ld21/ld21")
    if any(not x.is_file() for x in [*tools.values(), linker]):
        p.error("Independent assembler/linker is missing")
    inputs = sorted(args.corpus.glob("*.listing.json"))
    if not inputs:
        p.error("No Analyzer listing inputs")
    if args.output.exists():
        p.error("Refusing to overwrite result directory")
    args.output.mkdir(parents=True)
    listings = [checked_listing(path) for path in inputs]
    sources = sorted({normalize(row["text"], dialect) for data in listings for row in data["instructions"]})
    print("INPUTS", len(listings), "INSTRUCTIONS", sum(len(d["instructions"]) for d in listings), "UNIQUE_ASSEMBLER_SOURCES", len(sources), flush=True)
    cache = args.cache.resolve()
    encoded: dict[str, dict[str, AssemblyResult]] = {name: {} for name in tools}
    for name, executable in tools.items():
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            results = pool.map(lambda src: assemble(src, name, executable, linker, cache), sources)
            for i, (source, result) in enumerate(zip(sources, results), 1):
                encoded[name][source] = result
                if i % 1000 == 0 or i == len(sources):
                    print("ASSEMBLED", name, i, "/", len(sources), flush=True)
    summary: dict[str, Any] = {"scope": "Every explicitly listed instruction in the input saved Analyzer programs. Data/unclassified PM not counted as code.", "adapter_version": ADAPTER_VERSION, "dialect": dialect, "tools": {k: {"path": str(v), "sha256": hashlib.sha256(v.read_bytes()).hexdigest()} for k, v in tools.items()}, "linker_sha256": hashlib.sha256(linker.read_bytes()).hexdigest(), "programs": []}
    for data, file in zip(listings, inputs):
        rows = []
        counts = {name: Counter() for name in tools}
        both = Counter()
        for native in data["instructions"]:
            source = normalize(native["text"], dialect)
            item = {**native, "assembly_source": source, "comparison": {}}
            for name in tools:
                output = encoded[name][source]
                status = output.state
                if status == "ENCODED":
                    status = "EXACT" if output.machine_hex == native["bytes"] else "DIFFERENT_ENCODING"
                counts[name][status] += 1
                item["comparison"][name] = {"status": status, "machine_hex": output.machine_hex, "diagnostics": output.diagnostics if status != "EXACT" else ""}
            tags = [item["comparison"][name]["status"] for name in tools]
            combined_key = "SDK_EXACT" if args.sdk_root and tags == ["EXACT"] else "BOTH_EXACT" if tags == ["EXACT", "EXACT"] else "AT_LEAST_ONE_EXACT" if "EXACT" in tags else "NO_EXACT"
            both[combined_key] += 1
            rows.append(item)
        report = {"program": data["program"], "source_sha256": data["source_sha256"], "saved_version": data["version"], "program_path": data["path"], "instruction_denominator": len(rows), "native_functions": data["native_functions"], "input_sha256": hashlib.sha256(file.read_bytes()).hexdigest(), "counts": {k: dict(v) for k, v in counts.items()}, "combined": dict(both)}
        summary["programs"].append(report)
        (args.output / (data["program"] + ".comparison.json")).write_text(json.dumps({"summary": report, "instructions": rows}, ensure_ascii=False, indent=2) + "\n")
        print("PROGRAM_RESULT", json.dumps(report, ensure_ascii=False), flush=True)
    (args.output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    print("COMPLETE_ALL_INPUT_INSTRUCTIONS_ACCOUNTED", flush=True)


if __name__ == "__main__":
    main()
