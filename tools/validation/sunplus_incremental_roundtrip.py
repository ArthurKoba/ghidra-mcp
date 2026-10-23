"""Revalidate ONLY newly classified Sunplus 24-bit instructions after C/CFG recovery.

This is an evidence-expanding differential assembler pass, not re-running
already byte-verified legacy instructions or claiming 100% semantic coverage.
Program identity, all previously decoded bytes, and all native owners remain
checked. Input files are saved Ghidra MCP instruction-corpus JSON exports.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from typing import Callable
from tools.validation.sunplus_adsp_roundtrip import normalize, assemble


def _listing(file: Path) -> dict:
    data=json.loads(file.read_text())
    instructions=data.get('instructions')
    if not isinstance(instructions,list) or len(instructions)!=data.get('decoded_instructions'):
        raise ValueError('Incomplete saved native-instruction inventory')
    seen:dict[str,dict]={}
    for record in instructions:
        addr=record['address']
        word=record['bytes'].lower()
        if not addr.startswith('PM:') or len(word)!=6 or len(bytes.fromhex(word))!=3:
            raise ValueError('Expected valid PM24 native instruction address/bytes')
        if int(addr.split(':')[-1].split('.')[0],16)!=record['word_address']:
            raise ValueError('Native instruction word-address mismatch')
        if addr in seen:raise ValueError('Duplicate native instruction address')
        seen[addr]=record
    if len(data.get('source_sha256',''))!=64:
        raise ValueError('Missing original executable fingerprint')
    data['by_address']=seen
    return data


def compare_incremental(
    original: dict, updated: dict, encoder: Callable[[str], tuple[str,str,str]]
) -> dict:
    if original['program']!=updated['program'] or original['source_sha256']!=updated['source_sha256']:
        raise ValueError('Cannot compare unrelated executable programs')
    earlier=original['by_address'];latest=updated['by_address']
    if len(latest)<len(earlier):raise ValueError('Previously decoded source instructions missing')
    for addr,item in earlier.items():
        other=latest.get(addr)
        if other is None or item['bytes'].lower()!=other['bytes'].lower():
            raise ValueError('Old decoded PM24 native instruction changed/vanished at '+addr)
    old_native=original.get('native_total',original.get('native_functions'))
    new_native=updated.get('native_total',updated.get('native_functions'))
    if not isinstance(old_native,int) or not isinstance(new_native,int) or new_native<old_native:
        raise ValueError('Native function denominator unexpectedly decreased')
    fresh=[latest[x] for x in sorted(latest,key=lambda x:latest[x]['word_address']) if x not in earlier]
    if not fresh:raise ValueError('No newly classified instructions to validate')
    records=[]
    for record in fresh:
        normalized=normalize(record['text'],'sdk')
        state,encoded,diagnostics=encoder(normalized)
        exact=state=='ENCODED' and encoded.lower()==record['bytes'].lower()
        records.append({'address':record['address'],'native_word':record['bytes'],
                        'generated_sdk_assembly':normalized,'assembled_word':encoded,
                        'state':state,'exact':exact,'diagnostics':diagnostics[-180:]})
    return {
        'state':'VALIDATED_DELTA' if all(x['exact'] for x in records) else 'UNSUPPORTED_OR_DIFFERENT',
        'program':original['program'],'source_sha256':original['source_sha256'],
        'old_native_functions':old_native,'new_native_functions':new_native,
        'old_decoded_instructions':len(earlier),'new_decoded_instructions':len(latest),
        'new_native_instructions':len(records),'delta_exact':sum(x['exact'] for x in records),
        'unchanged_previously_verified_native_words':len(earlier),
        'has_unchecked_native_instructions':any(not x['exact'] for x in records),
        'scope':'byte-roundtrip only; native program execution and instruction semantics NOT_PROVEN',
        'delta':records}


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before',type=Path,required=True)
    parser.add_argument('--after',type=Path,required=True)
    parser.add_argument('--sdk-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cache',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('Refusing to overwrite existing comparison')
    as218x=args.sdk_root/'bin/as218x';ld21=args.sdk_root/'bin/ld21'
    if not as218x.is_file() or not ld21.is_file():parser.error('Missing independently built ADSP assembler or linker')
    before=_listing(args.before);after=_listing(args.after)
    result=compare_incremental(before,after,
       lambda source:(lambda r:(r.state,r.machine_hex,r.diagnostics))(
           assemble(source,'sdk-as218x',as218x,ld21,args.cache)))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print('INCREMENTAL_NATIVE_ASSEMBLER_RESULT',result['program'],
      'previous',result['old_decoded_instructions'],'new',result['new_native_instructions'],
      'exact',result['delta_exact'],'target_native_functions',result['new_native_functions'],
      'state',result['state'])
    if result['has_unchecked_native_instructions']:raise SystemExit(1)


if __name__=='__main__':main()
