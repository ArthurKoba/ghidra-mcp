"""Preserve ld21's resolved symbol map in standard ELF symbol sections.

Open21xx ld21 does not emit a symbol table in its executable. Its -L -m map
contains resolved word addresses. This module transfers that metadata only;
initialized PM/DM bytes and load addresses are checked unchanged by the caller.
"""
from dataclasses import dataclass
from pathlib import Path
import re
import struct

from ._contracts import MemorySegment, SdkError


@dataclass(frozen=True)
class LinkedSymbol:
    name: str
    space: str
    address: int
    size: int
    local: bool


def embed_link_map(elf_path: Path, map_path: Path,
                   segments: tuple[MemorySegment, ...]) -> tuple[LinkedSymbol, ...]:
    text = map_path.read_text(encoding="utf-8")
    if text.count("\nSymbols:\n") != 1 or not text.startswith("Open21xx Linker Version 0.7.6\n"):
        raise SdkError("Unrecognized pinned linker map format")
    pattern = re.compile(r"^\s+(\S+)\s+@(\*| )\s+(\S+)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+([0-9A-F]+)\s+.+$")
    by_space = {segment.space: segment for segment in segments}
    symbols = []
    for line in text.split("\nSymbols:\n", 1)[1].splitlines():
        if not line.strip() or line.strip().startswith("Name ") or line.strip() == "None":
            continue
        match = pattern.fullmatch(line)
        if not match:
            raise SdkError(f"Unrecognized symbol-map row: {line!r}")
        name, local, section, address, _, size = match.groups()
        space = {"program0": "PM", "pmdata0": "PM", "data0": "DM"}.get(section)
        if space not in by_space:
            raise SdkError(f"Symbol belongs to unmapped section: {section}")
        segment = by_space[space]
        address_value, size_value = int(address, 16), int(size, 16)
        if not segment.word_address <= address_value <= segment.word_address + segment.word_count:
            raise SdkError(f"Symbol outside its mapped {space}: {name}")
        if address_value + size_value > segment.word_address + segment.word_count:
            raise SdkError(f"Symbol extent outside its mapped {space}: {name}")
        if not name.isascii() or "\0" in name or len(name) > 1024:
            raise SdkError("Invalid linked symbol name")
        symbols.append(LinkedSymbol(name, space, address_value, size_value, local == "*"))
    if len(symbols) > 65535:
        raise SdkError("Too many symbols")
    symbols.sort(key=lambda item: (not item.local, item.name, item.space, item.address, item.size))
    raw = bytearray(elf_path.read_bytes())
    endian = "<" if raw[5] == 1 else ">"
    header = struct.unpack_from(endian + "HHIIIIIHHHHHH", raw, 16)
    if header[10] != 40:
        raise SdkError("Unsupported section-header width for metadata preservation")
    count, names_index = header[11], header[12]
    sections = [list(struct.unpack_from(endian + "10I", raw, header[5] + 40 * i)) for i in range(count)]
    names_section = sections[names_index]
    names = bytearray(raw[names_section[4]:names_section[4] + names_section[5]])
    indices = {}
    for index, section in enumerate(sections):
        name = names[section[0]:].split(b"\0", 1)[0].decode("ascii")
        if name in ("int_pm", "int_dm"):
            indices["PM" if name == "int_pm" else "DM"] = index
        if section[1] == 2:
            raise SdkError("Refusing to replace an existing ELF symbol table")
    symbol_strings = bytearray(b"\0")
    table = bytearray(16)  # mandatory null symbol
    for symbol in symbols:
        name_index = len(symbol_strings)
        symbol_strings.extend(symbol.name.encode("ascii") + b"\0")
        # PM labels remain NOTYPE; source labels alone do not prove a function.
        kind = 1 if symbol.space == "DM" and symbol.size else 0
        info = (0 if symbol.local else 0x10) | kind
        table.extend(struct.pack(endian + "IIIBBH", name_index, symbol.address,
                                 symbol.size, info, 0, indices[symbol.space]))
    sym_name = len(names)
    names.extend(b".symtab\0")
    str_name = len(names)
    names.extend(b".sdk_strtab\0")

    def append(payload: bytes | bytearray, alignment: int = 4) -> int:
        raw.extend(bytes((-len(raw)) % alignment))
        offset = len(raw)
        raw.extend(payload)
        return offset

    names_section[4], names_section[5] = append(names), len(names)
    symbols_offset = append(table)
    strings_offset = append(symbol_strings, 1)
    sections.append([sym_name, 2, 0, 0, symbols_offset, len(table), count + 1,
                     1 + sum(symbol.local for symbol in symbols), 4, 16])
    sections.append([str_name, 3, 0, 0, strings_offset, len(symbol_strings), 0, 0, 1, 0])
    new_table = append(b"".join(struct.pack(endian + "10I", *section) for section in sections))
    struct.pack_into(endian + "I", raw, 32, new_table)
    struct.pack_into(endian + "H", raw, 48, len(sections))
    elf_path.write_bytes(raw)
    return tuple(symbols)
