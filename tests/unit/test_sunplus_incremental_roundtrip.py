"""Newly discovered native DSP instructions must expand, never reset coverage."""
import json
from pathlib import Path
import pytest
from tools.validation.sunplus_incremental_roundtrip import _listing, compare_incremental


def _fixture(tmp_path: Path):
    before={'program':'test-dsp.bin','source_sha256':'a'*64,'native_total':1,
            'decoded_instructions':2,'instructions':[
                {'address':'PM:1000','word_address':4096,'bytes':'000000','text':'NOP','owner':'PM:1000'},
                {'address':'PM:1001','word_address':4097,'bytes':'0a000f','text':'RTS','owner':'PM:1000'}]}
    after=json.loads(json.dumps(before))
    after['native_total']=2
    after['decoded_instructions']=3
    after['instructions'].append({'address':'PM:1100','word_address':4352,'bytes':'0a000f',
                                    'text':'RTS','owner':'PM:1100'})
    originals=[]
    for name,content in [('before',before),('after',after)]:
        path=tmp_path/f'{name}.json';path.write_text(json.dumps(content));originals.append(path)
    return originals


def test_only_newly_decoded_native_words_are_reassembled(tmp_path: Path) -> None:
    a,b=[_listing(path) for path in _fixture(tmp_path)]
    calls=[]
    def encoder(source):
        calls.append(source)
        return ('ENCODED','0a000f','')
    report=compare_incremental(a,b,encoder)
    assert len(calls)==1
    assert report['old_native_functions']==1 and report['new_native_functions']==2
    assert report['new_native_instructions']==1 and report['delta_exact']==1
    assert report['unchanged_previously_verified_native_words']==2
    assert report['state']=='VALIDATED_DELTA'
    assert report['source_sha256']=='a'*64
    assert report['scope'].endswith('NOT_PROVEN')


def test_native_source_bytes_and_identity_are_invariants(tmp_path: Path) -> None:
    a,b=[_listing(path) for path in _fixture(tmp_path)]
    no=lambda source:('ENCODED','0a000f','')
    other=dict(b, source_sha256='b'*64)
    with pytest.raises(ValueError,match='unrelated'):compare_incremental(a,other,no)
    changed=json.loads(json.dumps(b,default=str))
    changed['by_address']['PM:1000']['bytes']='000001'
    with pytest.raises(ValueError,match='changed/vanished'):compare_incremental(a,changed,no)
    lost=dict(b,by_address={'PM:1000':b['by_address']['PM:1000']})
    with pytest.raises(ValueError,match='missing'):compare_incremental(a,lost,no)
    reduced=dict(b,native_total=0)
    with pytest.raises(ValueError,match='decreased'):compare_incremental(a,reduced,no)


def test_unsupported_assembly_does_not_create_false_full_coverage(tmp_path: Path) -> None:
    a,b=[_listing(path) for path in _fixture(tmp_path)]
    report=compare_incremental(a,b,lambda text:('ENCODED','deadbe','other ISA'))
    assert report['delta_exact']==0
    assert report['has_unchecked_native_instructions']
    assert report['state']=='UNSUPPORTED_OR_DIFFERENT'


def test_malformed_listing_rejected(tmp_path: Path) -> None:
    paths=_fixture(tmp_path)
    d=json.loads(paths[0].read_text());d['decoded_instructions']=3
    paths[0].write_text(json.dumps(d))
    with pytest.raises(ValueError,match='Incomplete'):_listing(paths[0])
