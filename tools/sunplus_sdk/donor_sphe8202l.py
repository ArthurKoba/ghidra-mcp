"""SPHE8202L donor CPU↔DSP interface adapter, **not** the SPHE8202R ABI.

Derived from the separately licensed SPHE8202L fork (commit
78143e63d9b66b0ba1c5c83dd1cc13c2f173a010). No donor code or ROM bytes are
shipped. These adapters are for comparative analysis only and MUST NOT be used
to assert a physical SPHE8202R hardware contract without independent evidence.

Sources: h/dsp3_codec_extern_param.h: pointer and three packed uint16 fields;
DSP3/dsp3_config.c:set_dsp3_pcm_value/get_dsp3_pcm_value: 3-byte big-endian
CPU-visible PCM buffer indexed in words; h/memmap.h: 1 KiB SDRAM pages and
uncached alias. DSP3/dsp3_if.c:AudioIOControl: first CPU command port=1
parameter, then port=0 command word, acknowledgement is read separately.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import struct
from typing import Iterable


# SPHE8202L MIPS32 data ABI, not the Ghidra DSP DM register width.
_DESCRIPTOR = struct.Struct("<IHHH")
PCM_WORD_BYTES = 3
CPU_BUFFER_PAGE_BYTES = 1024
SDRAM_UNCACHED_ALIAS = 0xA0000000


@dataclass(frozen=True)
class DonorCodecDescriptor:
    """Packed donor MIPS32 pointer + uiDSPIM + uiDSPDM + uiDSPPM, 10 bytes.

    The names are retained from the donor C declaration; their exact logical
    meaning/relationship to a SPHE8202R loader is deliberately unasserted.
    """
    dspcode_ptr: int
    ui_dsp_im: int
    ui_dsp_dm: int
    ui_dsp_pm: int

    @classmethod
    def from_bytes(cls, raw: bytes) -> "DonorCodecDescriptor":
        if len(raw) != _DESCRIPTOR.size:
            raise ValueError("Donor MIPS32 codec descriptor must be exactly 10 bytes")
        return cls(*_DESCRIPTOR.unpack(raw))

    def to_bytes(self) -> bytes:
        values = (self.dspcode_ptr, self.ui_dsp_im, self.ui_dsp_dm, self.ui_dsp_pm)
        if any(not isinstance(x, int) or x < 0 for x in values):
            raise ValueError("Descriptor values must be unsigned integers")
        if values[0] > 0xFFFFFFFF or any(x > 0xFFFF for x in values[1:]):
            raise ValueError("Descriptor value exceeds donor field width")
        return _DESCRIPTOR.pack(*values)


def cpu_visible_pcm_byte_offset(word_offset: int) -> int:
    """Offset within *external CPU-visible PCM SDRAM*, not internal DSP DM."""
    if type(word_offset) is not int or word_offset < 0:
        raise ValueError("PCM offset must be a nonnegative integer word index")
    return PCM_WORD_BYTES * word_offset


def cpu_visible_pcm_uncached_address(page_base: int, word_offset: int) -> int:
    """Donor: SDRAM_UNCACHED + 1024*PCM_YS + 3*word_offset.

    page_base is the *runtime page index* (MEM_PCMYA), not a fixed MMIO base.
    This function makes no claim about an actual SPHE8202R page assignment.
    """
    if type(page_base) is not int or page_base < 0:
        raise ValueError("PCM SDRAM page index must be a nonnegative integer")
    result = SDRAM_UNCACHED_ALIAS + CPU_BUFFER_PAGE_BYTES * page_base + cpu_visible_pcm_byte_offset(word_offset)
    if result > 0xFFFFFFFF:
        raise ValueError("PCM pointer exceeds 32-bit donor address space")
    return result


def pack_cpu_visible_pcm_words(values: Iterable[int]) -> bytes:
    """24-bit MSB-first CPU buffer packing; no implicit alignment/padding."""
    packed = bytearray()
    for value in values:
        if type(value) is not int or value < 0 or value > 0xFFFFFF:
            raise ValueError("Each CPU-visible PCM word must be 24-bit unsigned")
        packed.extend((value >> 16, (value >> 8) & 0xFF, value & 0xFF))
    return bytes(packed)


def unpack_cpu_visible_pcm_words(data: bytes) -> tuple[int, ...]:
    if len(data) % PCM_WORD_BYTES:
        raise ValueError("Packed CPU-visible PCM region is not word-aligned")
    return tuple(int.from_bytes(data[i : i + 3], "big") for i in range(0, len(data), 3))


class DonorAudioControlFamily(IntEnum):
    """Only explicitly observed *donor CPU command-family high bytes*.

    The lower byte is a command parameter/subcode; aliases are not inferred.
    These are unrelated to DSP-side resident mailbox command 0x62.
    """
    FLOW = 0x0200
    OUTPUT_MODE = 0x0300
    VOLUME = 0x1100


def donor_command_word(family: DonorAudioControlFamily, subtype: int) -> int:
    if not isinstance(family, DonorAudioControlFamily):
        raise ValueError("Unknown donor command family")
    if type(subtype) is not int or not 0 <= subtype <= 0xFF:
        raise ValueError("Donor command subcode must be an unsigned byte")
    return family.value | subtype


def donor_cpu_command_port_sequence(family: DonorAudioControlFamily, subtype: int, parameter: int) -> tuple[tuple[int, int], ...]:
    """Data port 1 then command port 0; no execution/ACK claim.

    Source AudioIOControl writes the optional payload first. This function is
    deliberately not a transaction runner and does not infer readback timing.
    """
    if type(parameter) is not int or not 0 <= parameter <= 0xFFFF:
        raise ValueError("Donor fixed-width parameter must be 16-bit")
    return ((1, parameter), (0, donor_command_word(family, subtype)))


@dataclass(frozen=True)
class DonorMemoryProfile:
    """Donor-side selected IM/DM/PM SDRAM page counts, not CPU/DSP ISA data."""
    im_pages: int
    dm_pages: int
    pm_pages: int

    @property
    def byte_lengths(self) -> tuple[int, int, int]:
        return tuple(pages * CPU_BUFFER_PAGE_BYTES for pages in
                     (self.im_pages, self.dm_pages, self.pm_pages))


def read_donor_memory_profiles(fork: "Path", chip_macro: str) -> dict[str, DonorMemoryProfile]:
    """Read *the selected donor variant*, never the generic table by default.

    h/memmap_dsp3.h selects memmap_dsp3_8202D.h for IC_8202D,
    IC_8202L and IC_8203A; other chips select memmap_dsp3_82XX.h.
    This is a comparison aid: the actual build defines and DSP-side mapping
    are external verification conditions, not inferred hardware facts.
    """
    from pathlib import Path
    import re

    if chip_macro not in {"IC_8202D", "IC_8202L", "IC_8203A", "IC_8200"}:
        raise ValueError("Unsupported donor memory-map selector")
    base = Path(fork) / "h"
    routing = (base / "memmap_dsp3.h").read_text(encoding="utf-8", errors="replace")
    selector = re.search(r"#if\s+defined\(IC_8202D\)\s*\|\|\s*defined\(IC_8202L\)\s*\|\|\s*defined\(IC_8203A\)", routing)
    if not selector or '"memmap_dsp3_8202D.h"' not in routing or '"memmap_dsp3_82XX.h"' not in routing:
        raise ValueError("Donor layout-selection source has changed")
    header = "memmap_dsp3_8202D.h" if chip_macro != "IC_8200" else "memmap_dsp3_82XX.h"
    source = (base / header).read_text(encoding="utf-8", errors="replace")
    found: dict[str, dict[str, int]] = {}
    for line in source.splitlines():
        # Exclude commented alternatives and only accept literal page counts.
        matched = re.fullmatch(r"\s*#define\s+DSP3_([A-Z0-9_]+)_(IM|DM|PM)\s+(\d+)\s*(?://.*)?\s*", line)
        if matched:
            name, region, value = matched.groups()
            slot = found.setdefault(name, {})
            if region in slot:
                raise ValueError(f"Duplicate donor memory profile {name}.{region}")
            slot[region] = int(value)
    complete = {}
    for name, numbers in found.items():
        if numbers.keys() != {"IM", "DM", "PM"}:
            raise ValueError(f"Partial donor memory profile: {name}")
        complete[name] = DonorMemoryProfile(numbers["IM"], numbers["DM"], numbers["PM"])
    if not complete:
        raise ValueError("No donor memory profiles were parsed")
    return dict(sorted(complete.items()))
