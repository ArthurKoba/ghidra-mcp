"""Source-independent Sunplus donor DSP code-container reader.

SPHE8202L donor .bin.gz files are raw DEFLATE streams followed by the normal
8-byte gzip CRC32/ISIZE trailer, but lack the ordinary 10-byte gzip header.
All 52 observed donor files pass independent decompression and checksum checks.
The decoded content remains proprietary to its source; do not ship it in SDK
packages, reports, or third-party projects without permission.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
import zlib

_MAX_ROM_BYTES = 2_000_000
_TRAILER = struct.Struct("<II")


@dataclass(frozen=True)
class DonorRawInfo:
    """Nonredistributable firmware metadata only; no original code in result."""
    packed_sha256: str
    decoded_sha256: str
    packed_bytes: int
    decoded_bytes: int
    padded_tail_zero_bytes: int
    pm_word_candidate_count: int


def unpack_raw_deflate_trailer(data: bytes, *, max_uncompressed: int = _MAX_ROM_BYTES) -> bytes:
    """Decode a complete donor stream; reject truncation, trailing junk and bombs.

    Raw bytes returned *solely* to the caller. They must not be interpreted as
    fully decoded executable instructions without Ghidra verification.
    """
    if not isinstance(data, bytes) or len(data) < 11:
        raise ValueError("Raw-DEFLATE DSP donor stream is too short")
    if not 0 < max_uncompressed <= _MAX_ROM_BYTES:
        raise ValueError("Unsupported maximum size")
    raw_stream, trailer = data[:-_TRAILER.size], data[-_TRAILER.size:]
    claimed_crc, claimed_size = _TRAILER.unpack(trailer)
    if claimed_size > max_uncompressed:
        raise ValueError("Uncompressed size exceeds configured bound")
    stream = zlib.decompressobj(wbits=-15)
    try:
        decoded = stream.decompress(raw_stream, max_uncompressed + 1)
        if len(decoded) > max_uncompressed or not stream.eof or stream.unused_data or stream.unconsumed_tail:
            raise ValueError("Incomplete or excessive raw-DEFLATE payload")
        decoded += stream.flush()
    except zlib.error as exc:
        raise ValueError("Invalid raw-DEFLATE DSP stream") from exc
    if len(decoded) != claimed_size:
        raise ValueError("DSP donor ISIZE does not match decoded length")
    if (zlib.crc32(decoded) & 0xFFFFFFFF) != claimed_crc:
        raise ValueError("DSP donor CRC32 mismatch")
    return decoded


def donor_blob_metadata(data: bytes) -> DonorRawInfo:
    """Calculate code-container metadata without retaining the proprietary ROM."""
    raw = unpack_raw_deflate_trailer(data)
    # In all 47 currently observed donor MIPS/DSP program images len%3=2,
    # those two bytes are zero; this is an observation, not a loader mandate.
    remainder = len(raw) % 3
    if remainder and any(raw[len(raw) - remainder :]):
        raise ValueError("Unaligned donor PM candidate has nonzero trailing data")
    return DonorRawInfo(
        packed_sha256=hashlib.sha256(data).hexdigest(),
        decoded_sha256=hashlib.sha256(raw).hexdigest(),
        packed_bytes=len(data),
        decoded_bytes=len(raw),
        padded_tail_zero_bytes=remainder,
        pm_word_candidate_count=len(raw) // 3,
    )


def validate_donor_payload(path: Path) -> DonorRawInfo:
    return donor_blob_metadata(path.read_bytes())


def pack_raw_deflate_trailer(decoded: bytes, *, level: int = 9) -> bytes:
    """Create the donor-style *container* from supplied, independently owned data.

    Wire format: RFC1951 raw DEFLATE stream followed by gzip's little-endian
    CRC32 and ISIZE trailer; **no gzip header**. Exact compression bytes need
    not match legacy `fgzip2.exe`. Loader execution/hardware compatibility is
    unknown and no proprietary image content is bundled.
    """
    if type(decoded) is not bytes or len(decoded) > _MAX_ROM_BYTES:
        raise ValueError("Decoded DSP image must be bounded bytes")
    if type(level) is not int or not 0 <= level <= 9:
        raise ValueError("DEFLATE level must be between 0 and 9")
    encoder = zlib.compressobj(level=level, wbits=-15)
    packed = encoder.compress(decoded) + encoder.flush()
    result = packed + _TRAILER.pack(zlib.crc32(decoded) & 0xFFFFFFFF,
                                     len(decoded) & 0xFFFFFFFF)
    if unpack_raw_deflate_trailer(result) != decoded:
        raise ValueError("Internal donor-container postcondition failed")
    return result


def prepared_donor_pm_word_payload(pm_image: bytes, *, legacy_two_byte_tail: bool = False) -> bytes:
    """Validate 24-bit code-word input; optional padding is **explicit**.

    Donor MIPS ROM images contain two zero tail bytes; five external DSP3
    archives do not. Padding is a donor packaging property, not a PM opcode.
    """
    if type(pm_image) is not bytes or len(pm_image) % 3:
        raise ValueError("Input DSP PM code must contain complete 24-bit words")
    raw = pm_image + (b"\x00\x00" if legacy_two_byte_tail else b"")
    if len(raw) > _MAX_ROM_BYTES:
        raise ValueError("Encoded DSP image exceeds output bound")
    return raw
