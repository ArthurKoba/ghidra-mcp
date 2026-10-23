"""Raw-DEFLATE donor program-image validation. No original ROM content exported."""
from pathlib import Path
import collections
import hashlib
import struct
import zlib
import pytest

from tools.sunplus_sdk.donor_raw import unpack_raw_deflate_trailer, donor_blob_metadata, validate_donor_payload


def pack_local_fixture(code: bytes) -> bytes:
    coder = zlib.compressobj(level=9, wbits=-15)
    return coder.compress(code) + coder.flush() + struct.pack('<II', zlib.crc32(code) & 0xFFFFFFFF, len(code))


def test_raw_deflate_with_crc_isize_and_valid_word_padding() -> None:
    source = bytes.fromhex('3c00033c000418024f0000000a001f000000')
    image = pack_local_fixture(source)
    assert unpack_raw_deflate_trailer(image) == source
    data = donor_blob_metadata(image)
    assert data.decoded_bytes == len(source)
    assert data.padded_tail_zero_bytes == 0
    assert data.pm_word_candidate_count == len(source) // 3
    assert data.decoded_sha256 == hashlib.sha256(source).hexdigest()


def test_crc_size_truncation_malformed_stream_and_extra_bytes_are_rejected() -> None:
    raw = pack_local_fixture(b'\x12\x34\x56\x00\x00')
    for damaged in (raw[:-1], raw[:-8], raw[:-9], raw[:-2] + b'xx',
                    raw[:-8] + struct.pack('<II', 0, 5),
                    raw[:-8] + struct.pack('<II', zlib.crc32(b'\x12\x34\x56\x00\x00'), 6),
                    raw[:-8] + b'\x00' + raw[-8:]):
        with pytest.raises(ValueError):unpack_raw_deflate_trailer(damaged)
    with pytest.raises(ValueError):unpack_raw_deflate_trailer(raw, max_uncompressed=3)
    assert donor_blob_metadata(raw).padded_tail_zero_bytes == 2
    with pytest.raises(ValueError):donor_blob_metadata(pack_local_fixture(b'abc\x01'))


def test_donor_fork_all_52_streams_and_41_unique_images_when_available() -> None:
    fork = Path(__file__).resolve().parents[3] / 'vendor/SPHE8202L/DSP3'
    if not fork.exists():
        pytest.skip('Pinned donor checkout absent')
    files = sorted(fork.rglob('*.bin.gz'))
    assert len(files) == 52
    cases = [validate_donor_payload(path) for path in files]
    assert all(record.decoded_bytes > 0 for record in cases)
    assert len({record.decoded_sha256 for record in cases}) == 41
    assert collections.Counter(record.padded_tail_zero_bytes for record in cases) == {2: 47, 0: 5}
    for path, record in zip(files, cases):
        if path.parent.name == 'MIPS':assert record.padded_tail_zero_bytes == 2
        else:assert record.padded_tail_zero_bytes == 0


def test_own_code_pm24_to_donor_container_roundtrip_with_explicit_padding() -> None:
    from tools.sunplus_sdk.donor_raw import pack_raw_deflate_trailer, prepared_donor_pm_word_payload
    words = bytes.fromhex("3c000318024f0a001f")
    for level in (0, 1, 6, 9):
        for legacy in (False, True):
            candidate = prepared_donor_pm_word_payload(words, legacy_two_byte_tail=legacy)
            wire = pack_raw_deflate_trailer(candidate, level=level)
            assert unpack_raw_deflate_trailer(wire) == candidate
            assert donor_blob_metadata(wire).pm_word_candidate_count == 3
            assert donor_blob_metadata(wire).padded_tail_zero_bytes == (2 if legacy else 0)
            import struct
            crc, size = struct.unpack_from('<II', wire, len(wire)-8)
            assert size == len(candidate)
            assert crc == zlib.crc32(candidate) & 0xffffffff
    with pytest.raises(ValueError):prepared_donor_pm_word_payload(words[:-1])
    with pytest.raises(ValueError):pack_raw_deflate_trailer(b'', level=10)
    with pytest.raises(ValueError):pack_raw_deflate_trailer(b'', level=-1)
    with pytest.raises(ValueError):pack_raw_deflate_trailer(b'\0'*(2_000_001))


def test_repack_all_52_donor_streams_without_claiming_identical_compressed_bytes() -> None:
    from tools.sunplus_sdk.donor_raw import pack_raw_deflate_trailer
    root = Path(__file__).resolve().parents[3] / 'vendor/SPHE8202L/DSP3'
    if not root.is_dir():
        pytest.skip('Pinned source checkout not present')
    samples = sorted(root.rglob('*.bin.gz'))
    assert len(samples)==52
    for source in samples:
        payload = unpack_raw_deflate_trailer(source.read_bytes())
        remade = pack_raw_deflate_trailer(payload, level=9)
        assert unpack_raw_deflate_trailer(remade)==payload
        assert donor_blob_metadata(remade).decoded_sha256 == donor_blob_metadata(source.read_bytes()).decoded_sha256
