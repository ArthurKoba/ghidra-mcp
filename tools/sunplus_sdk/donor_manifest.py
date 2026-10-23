"""Produce a license-safe *metadata-only* DSP donor comparison manifest.

Reads, but does not redistribute, SPHE8202L vendor code/ROM. The manifest is
not an Analyzer canonical project annotation and never claims SPHE8202R proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from .donor_sphe8202l import read_donor_memory_profiles

PINNED_FORK = '78143e63d9b66b0ba1c5c83dd1cc13c2f173a010'


def make_manifest(fork: Path) -> dict[str, object]:
    profile = read_donor_memory_profiles(fork, 'IC_8202L')
    generic = read_donor_memory_profiles(fork, 'IC_8200')
    paths = ['h/memmap_dsp3.h', 'h/memmap_dsp3_8202D.h',
             'h/memmap_dsp3_82XX.h', 'h/dsp3_codec_extern_param.h',
             'h/memmap.h', 'DSP3/dsp3_config.c', 'DSP3/dsp3_if.c',
             'DSP3/Makefile']
    digest = {name: hashlib.sha256((fork/name).read_bytes()).hexdigest() for name in paths}
    info = {}
    for code in sorted(profile.keys() & generic.keys()):
        a=profile[code];g=generic[code]
        info[code]={'ic8202l_pages':{'im':a.im_pages,'dm':a.dm_pages,'pm':a.pm_pages},
                    'generic_pages':{'im':g.im_pages,'dm':g.dm_pages,'pm':g.pm_pages},
                    'discrepant':a!=g}
    # Reports the conflict, not a guessed correction: source macro is 9,
    # donor's adjacent comment still says 38.7K for AC3 PM.
    raw=(fork/'h/memmap_dsp3_8202D.h').read_text(encoding='utf-8',errors='replace')
    pm=next(line for line in raw.splitlines() if re.match(r'^#define\s+DSP3_AC3_PM\b',line))
    contradictory=('38.7K' in pm and profile['AC3'].pm_pages==9)
    return {
        'schema':1,'fork_revision':PINNED_FORK,'evidence':'SPHE8202L CPU-side source only',
        'target_processor':'SPHE8202R','target_contract':'UNKNOWN',
        'donor_dsp_native_isa':'NOT_PROVIDED',
        'donor_dsp_assembler':'NOT_PROVIDED',
        'donor_dsp3_src_present':(fork/'DSP3_SRC').exists(),
        'donor_source_sha256':digest,
        'codec_count':len(info),'variant_differences':sum(row['discrepant'] for row in info.values()),
        'profiles':info,
        'comment_contradictions':[{
            'field':'DSP3_AC3_PM','macro_value_1kb_pages':9,
            'comment_claim':'38.7K','status':'CONTRADICTION'
        }] if contradictory else [],
        'restrictions':'Do not copy proprietary donor sources; no SPHE8202R equivalence without native and saved Analysis evidence.'
    }


def main() -> None:
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--fork',type=Path,required=True)
    cli.add_argument('--output',type=Path,required=True)
    args=cli.parse_args()
    if args.output.exists():cli.error('Refusing to overwrite an existing manifest')
    report=make_manifest(args.fork)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    print('DONOR_MANIFEST',args.output,'codecs',report['codec_count'],
          'layout_differences',report['variant_differences'],
          'comment_conflicts',len(report['comment_contradictions']))


if __name__=='__main__':main()
