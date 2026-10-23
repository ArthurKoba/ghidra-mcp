"""Function-scoped donor image evidence is byte equality, not semantic proof."""
import json
from pathlib import Path
import struct
import zlib
import pytest
from tools.sunplus_sdk.donor_provenance import compare_saved_native_to_donor


def _compressed(raw: bytes) -> bytes:
    obj = zlib.compressobj(wbits=-15)
    return obj.compress(raw) + obj.flush() + struct.pack('<II', zlib.crc32(raw) & 0xFFFFFFFF, len(raw))


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    corpus = tmp_path / 'listing'
    donor = tmp_path / 'donor'
    images = donor / 'MIPS'
    corpus.mkdir()
    images.mkdir(parents=True)
    content = [int(i * 0x10203 % 0x1000000).to_bytes(3, 'big') for i in range(1, 17)]
    code = []
    for k, value in enumerate(content):
        address = 0x100 + k
        owner = 'PM:0100' if k < 14 else None
        code.append({'address': f'PM:{address:04x}', 'word_address': address,
                     'bytes': value.hex(), 'owner': owner})
    listing = {
        'program': 'native-test.bin', 'source_sha256': '99'*32,
        'native_total': 1, 'decoded_instructions': len(code),
        'instructions': code,
        'functions': [{'address': 'PM:0100', 'name': 'FUN_PM_0100'}],
    }
    (corpus/'native-test.bin.instruction-corpus.json').write_text(json.dumps(listing))
    raw = b'\x11\x11\x11' + b''.join(content[:14]) + b'\xee\xee\xee\x00\x00'
    (images/'donor-alpha.bin.gz').write_bytes(_compressed(raw))
    (images/'donor-alias.bin.gz').write_bytes(_compressed(raw))
    (images/'donor-other.bin.gz').write_bytes(_compressed(b'\xaa'*45 + b'\x00\x00'))
    return corpus, donor


def test_only_bounded_function_owned_native_words_become_provenance(tmp_path: Path) -> None:
    corpus, donor = _fixture(tmp_path)
    report = compare_saved_native_to_donor(corpus, donor)
    assert report['native_function_denominator'] == 1
    assert report['native_functions_with_at_least_one_byte_match'] == 1
    assert report['donor_source_file_count'] == 3
    assert report['donor_unique_image_count'] == 2
    match = report['function_matches'][0]
    assert match['program'] == 'native-test.bin'
    assert match['owned_native_words'] == 14
    assert match['best_donor_match']['matched_native_words'] == 14
    assert match['best_donor_match']['best_run_words'] == 14
    assert match['best_donor_match']['target_PM_start'] == 0x100
    assert match['best_donor_match']['donor_word_start'] == 1
    assert match['best_donor_match']['donor_aliases'] == ['donor-alias.bin.gz', 'donor-alpha.bin.gz']
    assert 'source_semantics' in report and report['source_semantics'] == 'NOT_PROVEN'
    assert b'\x11\x11\x11'.hex() not in json.dumps(report)


def test_high_entropy_and_strict_inputs_guard_against_spurious_matches(tmp_path: Path) -> None:
    corpus, donor = _fixture(tmp_path)
    assert compare_saved_native_to_donor(corpus, donor, minimum=15)['native_functions_with_at_least_one_byte_match']==0
    with pytest.raises(ValueError):compare_saved_native_to_donor(corpus, donor, minimum=3)
    with pytest.raises(ValueError):compare_saved_native_to_donor(corpus, donor, distinct=13)
    file = next(corpus.glob('*.json'))
    document = json.loads(file.read_text())
    document['instructions'][0]['word_address'] = 0x123
    file.write_text(json.dumps(document))
    with pytest.raises(ValueError):compare_saved_native_to_donor(corpus, donor)
