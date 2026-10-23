"""Donor SPHE8202L ABI comparison tests; no inherited SPHE8202R hardware claim."""
import random
from pathlib import Path
import re
import struct
import pytest
from tools.sunplus_sdk.donor_sphe8202l import (
    DonorCodecDescriptor, DonorAudioControlFamily,
    cpu_visible_pcm_byte_offset, cpu_visible_pcm_uncached_address,
    pack_cpu_visible_pcm_words, unpack_cpu_visible_pcm_words,
    donor_cpu_command_port_sequence, donor_command_word,
)


def test_donor_codec_descriptor_is_packed_little_endian_mips32() -> None:
    descriptor = DonorCodecDescriptor(0xA1123344, 0x0102, 0x0304, 0x0506)
    raw = descriptor.to_bytes()
    assert len(raw) == 10
    assert raw == bytes.fromhex("443312a1020104030605")
    assert DonorCodecDescriptor.from_bytes(raw) == descriptor


def test_donor_descriptor_rejects_truncation_overflow_and_sign() -> None:
    with pytest.raises(ValueError):DonorCodecDescriptor.from_bytes(b"\0" * 9)
    with pytest.raises(ValueError):DonorCodecDescriptor.from_bytes(b"\0" * 11)
    with pytest.raises(ValueError):DonorCodecDescriptor(0x1_0000_0000, 0, 0, 0).to_bytes()
    with pytest.raises(ValueError):DonorCodecDescriptor(0, -1, 0, 0).to_bytes()
    with pytest.raises(ValueError):DonorCodecDescriptor(0, 0, 0x10000, 0).to_bytes()


def test_external_pcm_packing_big_endian_24_bit_and_roundtrip() -> None:
    words = (0x123456, 0, 0x800001, 0xFFFFFF)
    assert pack_cpu_visible_pcm_words(words) == bytes.fromhex("123456000000800001ffffff")
    assert unpack_cpu_visible_pcm_words(pack_cpu_visible_pcm_words(words)) == words
    rng = random.Random(8202)
    values = [rng.getrandbits(24) for _ in range(8192)]
    assert unpack_cpu_visible_pcm_words(pack_cpu_visible_pcm_words(values)) == tuple(values)
    with pytest.raises(ValueError):unpack_cpu_visible_pcm_words(b"ab")
    with pytest.raises(ValueError):pack_cpu_visible_pcm_words((0x1000000,))
    with pytest.raises(ValueError):pack_cpu_visible_pcm_words((-1,))


def test_cpu_visible_pcm_window_addressing_not_dsp_data_memory() -> None:
    assert cpu_visible_pcm_byte_offset(0) == 0
    assert cpu_visible_pcm_byte_offset(0x20) == 0x60
    assert cpu_visible_pcm_uncached_address(0, 0) == 0xA0000000
    assert cpu_visible_pcm_uncached_address(0x50, 0x20) == 0xA0014060
    assert cpu_visible_pcm_uncached_address(0x50, 0) + 3 * 32 == cpu_visible_pcm_uncached_address(0x50, 32)
    with pytest.raises(ValueError):cpu_visible_pcm_uncached_address(0x600000, 0)
    with pytest.raises(ValueError):cpu_visible_pcm_byte_offset(-1)


def test_donor_control_port_sequence_and_scope() -> None:
    assert donor_command_word(DonorAudioControlFamily.FLOW, 3) == 0x203
    assert donor_cpu_command_port_sequence(DonorAudioControlFamily.OUTPUT_MODE, 6, 0x0102) == ((1, 0x0102), (0, 0x306))
    assert donor_cpu_command_port_sequence(DonorAudioControlFamily.VOLUME, 0, 0) == ((1, 0), (0, 0x1100))
    with pytest.raises(ValueError):donor_command_word(DonorAudioControlFamily.FLOW, 0x100)
    with pytest.raises(ValueError):donor_cpu_command_port_sequence(DonorAudioControlFamily.FLOW, 1, 0x10000)


def test_source_evidence_contract_when_local_donor_checkout_exists() -> None:
    fork = Path(__file__).resolve().parents[3] / "vendor/SPHE8202L"
    if not (fork / "DSP3/dsp3_config.c").is_file():
        pytest.skip("SPHE8202L vendor checkout not available")
    desc=(fork/"h/dsp3_codec_extern_param.h").read_text()
    memory=(fork/"h/memmap.h").read_text()
    config=(fork/"DSP3/dsp3_config.c").read_text(encoding="utf-8", errors="replace")
    commands=(fork/"DSP3/dsp3_if.c").read_text(encoding="utf-8", errors="replace")
    assert re.search(r"BYTE\s*\*\s*pDSPcode\s+__attribute__\s*\(\(packed\)\)",desc)
    assert all(re.search(r"UINT16\s+uiDSP"+field+r"\s+__attribute__\s*\(\(packed\)\)",desc) for field in ("IM","DM","PM"))
    assert "1024*(PCM_YS+(y))+(x)" in memory
    assert "SDRAM_BASE_UNCACHED" in memory
    assert "get_dsp_pcm_uptr(x_off*3, 0)" in config
    assert all(fragment in config for fragment in ("(value>>16) & 0xff", "(value>>8) & 0xff", "(value>>0) & 0xff"))
    assert "regs0->dsp24_port[1] = wParam;" in commands
    assert "regs0->dsp24_port[0] = 0x0200 | cType;" in commands
    assert "regs0->dsp24_port[0] = 0x0300 | cType;" in commands


def test_donor_chip_specific_memory_variants_do_not_collapse() -> None:
    from tools.sunplus_sdk.donor_sphe8202l import read_donor_memory_profiles
    fork = Path(__file__).resolve().parents[3] / "vendor/SPHE8202L"
    if not (fork / "h/memmap_dsp3.h").is_file():
        pytest.skip("SPHE8202L comparison checkout unavailable")
    active = read_donor_memory_profiles(fork, "IC_8202L")
    generic = read_donor_memory_profiles(fork, "IC_8200")
    assert active["AC3"].byte_lengths == (37 * 1024, 210 * 1024, 9 * 1024)
    assert generic["AC3"].byte_lengths == (38 * 1024, 169 * 1024, 39 * 1024)
    assert active["AC3"] != generic["AC3"]
    assert (active["DTS_8202"].im_pages, active["DTS_8202"].dm_pages, active["DTS_8202"].pm_pages) == (29, 196, 12)
    assert (generic["DTS_8202"].im_pages, generic["DTS_8202"].dm_pages, generic["DTS_8202"].pm_pages) == (27, 196, 12)
    assert active == read_donor_memory_profiles(fork, "IC_8202D")
    assert active == read_donor_memory_profiles(fork, "IC_8203A")
    assert len(active) >= 30
    for name, profile in active.items():
        assert all(x > 0 for x in profile.byte_lengths), name
    with pytest.raises(ValueError):read_donor_memory_profiles(fork, "IC_SPHE8202R")


def test_donor_manifest_is_metadata_only_and_flags_source_conflicts() -> None:
    from tools.sunplus_sdk.donor_manifest import make_manifest
    fork = Path(__file__).resolve().parents[3] / "vendor/SPHE8202L"
    if not (fork / "h/memmap_dsp3_8202D.h").exists():
        pytest.skip("Pinned vendor checkout not present")
    report = make_manifest(fork)
    assert report['codec_count'] >= 30
    assert report['variant_differences'] > 0
    assert report['donor_dsp3_src_present'] is False
    assert report['target_contract'] == 'UNKNOWN'
    assert report['profiles']['AC3']['ic8202l_pages'] == {'im':37,'dm':210,'pm':9}
    assert report['profiles']['AC3']['discrepant'] is True
    assert report['comment_contradictions'][0]['status'] == 'CONTRADICTION'
    assert all(len(value)==64 for value in report['donor_source_sha256'].values())
