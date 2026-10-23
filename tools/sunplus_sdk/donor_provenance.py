"""Function-scoped native word equality against external Sunplus donor images.

No donor ROM is copied to outputs and no byte-identical match is interpreted
as a source-level function contract. Saved Ghidra listing rows are the only
recognized native instructions: PM data/unclassified gaps never become code.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
from typing import Any

from .donor_raw import donor_blob_metadata, unpack_raw_deflate_trailer


MIN_RUN = 12
MIN_DISTINCT_WORDS = 7


def _load_saved_program(path: Path) -> dict[str, Any]:
    doc = json.loads(path.read_text())
    code = doc['instructions']
    if not code or len(code) != doc['decoded_instructions']:
        raise ValueError(f'No complete native saved instruction inventory: {path}')
    words: dict[int, tuple[bytes, str | None]] = {}
    for i in code:
        address = i['word_address']
        word = bytes.fromhex(i['bytes'])
        if len(word) != 3 or address in words or i['address'] != f'PM:{address:04x}':
            raise ValueError(f'Invalid saved code offset/word identity: {i}')
        words[address] = (word, i.get('owner'))
    names = {f['address']: f['name'] for f in doc.get('functions', [])}
    if not names:
        raise ValueError('Saved native function inventory missing')
    if doc['native_total'] != len(doc['functions']):
        raise ValueError('Native function denominator disagreement')
    return {'program':doc['program'],'words':words,'functions':names,'source_sha256':doc['source_sha256']}


def _native_windows(
    programs: list[dict[str, Any]], *, minimum: int, distinct: int
) -> dict[bytes, list[tuple[str, int]]]:
    index: dict[bytes, list[tuple[str, int]]] = defaultdict(list)
    for profile in programs:
        words = profile['words']
        for at, (word, owner) in words.items():
            if not owner:continue
            seq=[]
            for delta in range(minimum):
                nxt=words.get(at+delta)
                if not nxt or nxt[1]!=owner:break
                seq.append(nxt[0])
            if len(seq)==minimum and len(set(seq))>=distinct:
                index[b''.join(seq)].append((profile['program'],at))
    return index


def compare_saved_native_to_donor(
    corpus: Path, donor_root: Path, *, minimum: int=MIN_RUN,
    distinct: int=MIN_DISTINCT_WORDS, max_results_per_function: int=5
) -> dict[str, Any]:
    if not 4<=minimum<=64 or not 2<=distinct<=minimum:
        raise ValueError('Require bounded meaningful source entropy/length')
    if not 1<=max_results_per_function<=20:
        raise ValueError('Unbounded per-function evidence')
    files=sorted(Path(corpus).glob('*.instruction-corpus.json'))
    if not files:raise ValueError('Missing saved native program listings')
    programs=[_load_saved_program(p) for p in files]
    if len({p['program'] for p in programs})!=len(programs):
        raise ValueError('Duplicate program listing')
    profiles={p['program']:p for p in programs}
    indexed=_native_windows(programs,minimum=minimum,distinct=distinct)
    records:dict[tuple[str,str,str],dict[str,Any]]={}
    donor_hashes:dict[str,dict[str,Any]]={}
    images=sorted(Path(donor_root).glob('MIPS/*.bin.gz'))
    if not images:raise ValueError('No executable donor images in MIPS/*.bin.gz')
    for image in images:
        encoded=image.read_bytes()
        meta=donor_blob_metadata(encoded)
        raw=unpack_raw_deflate_trailer(encoded)
        if meta.padded_tail_zero_bytes != 2 or raw[-2:]!=b'\0\0':
            raise ValueError('Donor executable image lacks observed two-byte PM padding')
        program_image=raw[:-2]
        assert len(program_image)%3==0
        donor=donor_hashes.setdefault(meta.decoded_sha256,{
            'sha256':meta.decoded_sha256,'files':[],'pm_word_candidates':len(program_image)//3})
        donor['files'].append(image.name)
        if len(donor['files'])!=1:
            continue  # the ROM is identical: duplicate names are aliases, not new evidence
        donor_words=[program_image[i:i+3] for i in range(0,len(program_image),3)]
        seen:set[tuple[str,int,int,int]] = set()
        for daddr in range(len(donor_words)-minimum+1):
            key=b''.join(donor_words[daddr:daddr+minimum])
            hits=indexed.get(key)
            if not hits:continue
            for program,word_at in hits:
                word_map=profiles[program]['words']
                owner=word_map[word_at][1]
                assert owner is not None
                pm,dpm=word_at,daddr
                while pm>0 and dpm>0 and (pm-1 in word_map) and word_map[pm-1]==(donor_words[dpm-1],owner):
                    pm-=1;dpm-=1
                matched=0
                while dpm+matched<len(donor_words):
                    cur=word_map.get(pm+matched)
                    if cur!=(donor_words[dpm+matched],owner):break
                    matched+=1
                if matched<minimum:continue
                identity=(program,pm,dpm,matched)
                if identity in seen:continue
                seen.add(identity)
                slot=records.setdefault((program,owner,meta.decoded_sha256),{
                    'matched_word_addresses':set(), 'best_run':(0,0,0)})
                slot['matched_word_addresses'].update(range(pm,pm+matched))
                if matched>slot['best_run'][0]:slot['best_run']=(matched,pm,dpm)
    owners:dict[tuple[str,str],set[int]]=defaultdict(set)
    for p in programs:
        for at,(_,owner) in p['words'].items():
            if owner:owners[(p['program'],owner)].add(at)
    scope=[]
    for (program,owner),function_addresses in sorted(owners.items()):
        candidates=[]
        for (name,entry,sha),match in records.items():
            if name!=program or entry!=owner:continue
            assert match['matched_word_addresses']<=function_addresses
            n,start,donor_offset=match['best_run']
            candidates.append({'donor_sha256':sha,
                'donor_aliases':sorted(donor_hashes[sha]['files']),
                'matched_native_words':len(match['matched_word_addresses']),
                'best_run_words':n,'target_PM_start':start,'donor_word_start':donor_offset})
        candidates.sort(key=lambda row:(-row['matched_native_words'],-row['best_run_words'],row['donor_sha256']))
        if candidates:
            scope.append({'program':program,'owner':owner,
                          'function_name':profiles[program]['functions'].get(owner,'UNKNOWN'),
                          'owned_native_words':len(function_addresses),
                          'best_donor_match':candidates[0],
                          'candidates':candidates[:max_results_per_function],
                          'status':'EXACT_BYTE_FRAGMENTS_ONLY'})
    all_owners=set(owners)
    report={
        'schema_version':1,'scope':'Only native 24-bit Ghidra instruction records with known function owner; data and unowned PM excluded',
        'donor_source':'SPHE8202L CPU-side release; only MIPS DSP ROM raw-DEFLATE images',
        'target_contract':'UNKNOWN', 'source_semantics':'NOT_PROVEN',
        'minimum_consecutive_words':minimum,'minimum_distinct_words_in_window':distinct,
        'saved_programs':[{k:p[k] for k in ('program','source_sha256')}|
                          {'native_function_count':len(p['functions']),
                           'decoded_instruction_count':len(p['words'])} for p in programs],
        'donor_source_file_count':len(images),'donor_unique_image_count':len(donor_hashes),
        'native_function_denominator':len(all_owners),
        'native_functions_with_at_least_one_byte_match':len(scope),
        'function_matches':scope,
    }
    return report


def main() -> None:
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--corpus',type=Path,required=True)
    cli.add_argument('--donor-root',type=Path,required=True)
    cli.add_argument('--output',type=Path,required=True)
    cli.add_argument('--min-run',type=int,default=MIN_RUN)
    args=cli.parse_args()
    if args.output.exists():cli.error('Refusing to overwrite results')
    report=compare_saved_native_to_donor(args.corpus,args.donor_root,minimum=args.min_run)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print('DONOR_FUNCTION_PROVENANCE',report['donor_source_file_count'], 'donor_images,',
          report['donor_unique_image_count'],'unique,',report['native_functions_with_at_least_one_byte_match'],
          'matched of',report['native_function_denominator'],'native owner functions')
    for entry in report['function_matches']:
        if entry['function_name'].startswith('PCM_AutoEntry') or entry['function_name'].startswith('SetResident'):
            print('INTERESTING',entry['program'],entry['function_name'],entry['best_donor_match']['matched_native_words'])


if __name__=='__main__':main()
