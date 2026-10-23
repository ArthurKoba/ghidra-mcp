"""Read only the ELF container emitted by the pinned Open21xx linker."""
import struct
from dataclasses import dataclass
from pathlib import Path

from ._contracts import MemorySegment, SdkError


@dataclass(frozen=True)
class _Section:
    name_offset: int
    kind: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int


def linked_segments(path: Path) -> tuple[MemorySegment, ...]:
    if path.stat().st_size > 4 * 1024 * 1024:
        raise SdkError("SDK ELF exceeds the bounded 4 MiB container limit")
    raw = path.read_bytes()
    if len(raw) < 52 or raw[:5] != b"\x7fELF\x01" or raw[5] not in (1, 2):
        raise SdkError("Expected an ELF32 Open21xx image")
    endian = "<" if raw[5] == 1 else ">"
    header = struct.unpack_from(endian + "HHIIIIIHHHHHH", raw, 16)
    if header[0] != 2 or header[1] != 0x6423 or header[2] != 1:
        raise SdkError("Expected linked ET_EXEC / EM_ADSP218X image; raw objects are not accepted")
    offset, width, count, names_index = header[5], header[10], header[11], header[12]
    if width < 40 or not 0 < count <= 4096 or offset < 52 or offset + width * count > len(raw):
        raise SdkError("Invalid ELF section directory")
    if not 0 <= names_index < count:
        raise SdkError("Invalid ELF section-name table")
    sections = tuple(_Section(*struct.unpack_from(endian + "IIIIIIIIII", raw, offset + i * width)) for i in range(count))

    def payload(section: _Section) -> bytes:
        if section.offset + section.size > len(raw):
            raise SdkError("ELF section extends beyond image")
        return raw[section.offset:section.offset + section.size]

    names = payload(sections[names_index])

    def name_at(data: bytes, index: int) -> str:
        if not 0 <= index < len(data) or b"\0" not in data[index:]:
            raise SdkError("Invalid ELF string offset")
        return data[index:].split(b"\0", 1)[0].decode("ascii", errors="strict")

    output = []
    seen = set()
    for section in sections:
        if section.kind == 0:
            continue
        name = name_at(names, section.name_offset)
        if section.kind in (4, 9) and section.size:
            raise SdkError(f"Unapplied relocations remain in {name}")
        if section.kind == 2:
            if section.entry_size != 16 or section.size % 16 or not 0 <= section.link < count:
                raise SdkError("Invalid ELF symbol table")
            table, strings = payload(section), payload(sections[section.link])
            for start in range(0, len(table), 16):
                symname, _, _, info, _, shndx = struct.unpack_from(endian + "IIIBBH", table, start)
                if shndx == 0 and info >> 4 == 1 and symname:
                    raise SdkError(f"Unresolved symbol: {name_at(strings, symname)}")
        if section.flags & 2 and section.size:
            if name not in ("int_pm", "int_dm") or section.kind != 1:
                raise SdkError(f"Unrecognized initialized/mapped section: {name}")
            if name in seen:
                raise SdkError(f"Duplicate output section: {name}")
            seen.add(name)
            word_bytes, space = (3, "PM") if name == "int_pm" else (2, "DM")
            if section.size % word_bytes:
                raise SdkError(f"Partial {space} word in output")
            output.append(MemorySegment(name, space, section.address, word_bytes, payload(section)))
    if not any(segment.space == "PM" for segment in output):
        raise SdkError("Output contains no initialized PM")
    return tuple(output)
