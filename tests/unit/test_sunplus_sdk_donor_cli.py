"""Public, independently executable SDK commands for user-supplied DSP data."""
from pathlib import Path
import json
import subprocess
import sys
import zlib
import struct


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, '-m', 'tools.sunplus_sdk', *args],
                          capture_output=True, text=True, check=False, timeout=30)


def test_sdk_donor_pack_unpack_24bit_words_preserve_source(tmp_path: Path) -> None:
    source=tmp_path/'own.pm.bin';source.write_bytes(bytes.fromhex('0a000f3c000318024f'))
    packed=tmp_path/'own.donor.gz';roundtrip=tmp_path/'restored.pm.bin'
    result=_cli('donor-pack',str(source),'--output',str(packed),'--legacy-two-byte-tail')
    assert result.returncode==0,result.stderr
    assert json.loads(result.stdout)['target_execution']=='NOT_VERIFIED'
    decoded=zlib.decompressobj(-15)
    code=decoded.decompress(packed.read_bytes())+decoded.flush()
    assert code==source.read_bytes()+b'\x00\x00'
    assert decoded.eof and len(decoded.unused_data)==8
    crc,size=struct.unpack('<II',decoded.unused_data)
    assert crc==zlib.crc32(code) & 0xffffffff and size==len(code)
    result=_cli('donor-unpack',str(packed),'--output',str(roundtrip),'--strip-two-byte-tail')
    assert result.returncode==0,result.stderr
    assert roundtrip.read_bytes()==source.read_bytes()
    assert _cli('donor-pack',str(source),'--output',str(packed)).returncode!=0
    assert _cli('donor-unpack',str(packed),'--output',str(roundtrip)).returncode!=0


def test_sdk_donor_pack_rejects_partial_words_and_unsupported_padding(tmp_path: Path) -> None:
    source=tmp_path/'partial.pm.bin';source.write_bytes(b'\x00\x11')
    result=_cli('donor-pack',str(source),'--output',str(tmp_path/'bad.gz'))
    assert result.returncode!=0 and '24-bit' in result.stderr
    assert not (tmp_path/'bad.gz').exists()
    full=tmp_path/'full.pm.bin';full.write_bytes(bytes.fromhex('0a000f'))
    result=_cli('donor-pack',str(full),'--output',str(tmp_path/'full.gz'))
    assert result.returncode==0,result.stderr
    invalid_strip=_cli('donor-unpack',str(tmp_path/'full.gz'),
                       '--output',str(tmp_path/'failed.pm.bin'),'--strip-two-byte-tail')
    assert invalid_strip.returncode!=0
    assert not (tmp_path/'failed.pm.bin').exists()
