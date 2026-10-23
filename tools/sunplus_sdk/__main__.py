import argparse
import json
import os
from pathlib import Path

from . import MemoryLayout, SdkError, Toolchain, build_image, linked_segments


def main() -> None:
    parser = argparse.ArgumentParser(description="Experimental Sunplus DSP assembly/link SDK (not a flash writer)")
    parser.add_argument("--sdk-root", type=Path,
                        default=Path(os.environ.get("SUNPLUS_DSP_SDK_ROOT", Path(__file__).resolve().parents[2])))
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="Assemble .dsp files and link PM24/DM16 images")
    build.add_argument("sources", nargs="+", type=Path)
    build.add_argument("--output", required=True, type=Path)
    build.add_argument("--pm-base", type=lambda value: int(value, 0), default=0)
    build.add_argument("--entry-word", type=lambda value: int(value, 0), help="Explicit Ghidra/ELF entry in PM word units")
    build.add_argument("--dm-base", type=lambda value: int(value, 0), default=0)
    inspect = commands.add_parser("inspect", help="Validate a linked Open21xx ELF image")
    inspect.add_argument("image", type=Path)
    commands.add_parser("doctor", help="Check SDK assembler/linker availability")
    donor = commands.add_parser("donor-map", help="Export CPU-visible DSP layouts from an available SPHE8202L source checkout")
    donor.add_argument("--fork", type=Path, required=True)
    donor.add_argument("--output", type=Path, required=True)
    compare = commands.add_parser("donor-match", help="Compare native Ghidra PM instruction identities to unpacked donor ROM (metadata only)")
    compare.add_argument("--corpus", type=Path, required=True)
    compare.add_argument("--fork", type=Path, required=True)
    compare.add_argument("--output", type=Path, required=True)
    compare.add_argument("--min-run", type=int, default=12)
    pack = commands.add_parser("donor-pack", help="Experimental SPHE8202L raw-DEFLATE container for your own PM24 image")
    pack.add_argument("image", type=Path)
    pack.add_argument("--output", required=True, type=Path)
    pack.add_argument("--legacy-two-byte-tail", action="store_true")
    pack.add_argument("--level", type=int, default=9)
    unpack = commands.add_parser("donor-unpack", help="Extract donor container to a local file (never bundled in SDK)")
    unpack.add_argument("archive", type=Path)
    unpack.add_argument("--output", required=True, type=Path)
    unpack.add_argument("--strip-two-byte-tail", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "doctor":
            tools = Toolchain(args.sdk_root)
            print(json.dumps({name: str(tools.executable(name)) for name in ("as218x", "ld21")}, indent=2))
        elif args.command == "donor-map":
            from .donor_manifest import make_manifest
            if args.output.exists():
                raise SdkError("Refusing to overwrite existing donor source comparison")
            report = make_manifest(args.fork)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
            print(json.dumps({"manifest": str(args.output), "profiles": report["codec_count"],
                              "variant_differences": report["variant_differences"],
                              "target_contract": report["target_contract"]}, indent=2))
        elif args.command == "donor-match":
            from .donor_provenance import compare_saved_native_to_donor
            if args.output.exists():
                raise SdkError("Refusing to overwrite existing donor program comparison")
            report = compare_saved_native_to_donor(args.corpus, args.fork / "DSP3",
                                                   minimum=args.min_run)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
            print(json.dumps({
                "manifest": str(args.output),
                "donor_unique_images": report["donor_unique_image_count"],
                "target_functions": report["native_function_denominator"],
                "matched_functions": report["native_functions_with_at_least_one_byte_match"],
                "semantic_coverage": "NOT_PROVEN",
            }, indent=2))
        elif args.command == "donor-pack":
            from .donor_raw import pack_raw_deflate_trailer, prepared_donor_pm_word_payload
            if args.output.exists():
                raise SdkError("Refusing to overwrite existing donor container")
            raw = prepared_donor_pm_word_payload(args.image.read_bytes(),
                                                  legacy_two_byte_tail=args.legacy_two_byte_tail)
            result = pack_raw_deflate_trailer(raw, level=args.level)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(result)
            print(json.dumps({"output": str(args.output), "decoded_bytes": len(raw),
                              "packed_bytes": len(result), "target_execution": "NOT_VERIFIED"}, indent=2))
        elif args.command == "donor-unpack":
            from .donor_raw import unpack_raw_deflate_trailer
            if args.output.exists():
                raise SdkError("Refusing to overwrite extracted donor bytes")
            decoded = unpack_raw_deflate_trailer(args.archive.read_bytes())
            if args.strip_two_byte_tail:
                if len(decoded) % 3 != 2 or not decoded.endswith(b"\x00\x00"):
                    raise SdkError("No verified two-byte trailing zero padding to remove")
                decoded = decoded[:-2]
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(decoded)
            print(json.dumps({"output": str(args.output), "decoded_bytes": len(decoded),
                              "source_semantics": "UNKNOWN"}, indent=2))
        elif args.command == "inspect":
            segments = linked_segments(args.image)
            print(json.dumps([{"space": item.space, "word_address": item.word_address,
                               "word_bytes": item.word_bytes, "word_count": item.word_count} for item in segments], indent=2))
        else:
            result = build_image(tuple(args.sources), args.output, Toolchain(args.sdk_root),
                                 MemoryLayout(pm_start=args.pm_base, dm_start=args.dm_base), entry_word=args.entry_word)
            print(result.manifest_path)
    except (SdkError, OSError, UnicodeError, ValueError, KeyError) as exc:
        parser.exit(2, f"SDK error: {exc}\n")


if __name__ == "__main__":
    main()
