"""Assemble a relocatable developer SDK from pinned, already built tool sources.

No network calls, firmware changes, installation or Analyzer mutation occurs.
The package includes corresponding GPL source and a Ghidra candidate, not an
assertion of hardware compatibility or full processor acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import zipfile

STAMP = (2026, 10, 15, 0, 0, 0)


def run(argv: list[str], cwd: Path | None = None) -> None:
    subprocess.run(argv, cwd=cwd, check=True, timeout=120)


def archive_zip(path: Path, files: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED) as output:
        for name, content in sorted(files.items()):
            info = zipfile.ZipInfo(name, STAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            output.writestr(info, content)
    with zipfile.ZipFile(path) as verify:
        assert set(verify.namelist()) == set(files)
        assert all(verify.read(name) == content for name, content in files.items())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool-source", type=Path, required=True)
    parser.add_argument("--upstream-repo", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path, required=True)
    parser.add_argument("--jdk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if output.exists():
        parser.error("Output directory must not exist")
    upstream = subprocess.check_output(["git", "-C", str(args.upstream_repo), "rev-parse", "HEAD"], text=True).strip()
    if upstream != "55259d045abf100b83a040c3d2811613855ee96b":
        parser.error("Unexpected Open21xx source revision")
    package = output / "sunplus-dsp-sdk-0.1-candidate"
    package.mkdir(parents=True)
    for name in ("bin", "lib/sunplus_sdk", "examples", "patches", "source/open21xx", "source/ghidra", "LICENSES", "ghidra"):
        (package / name).mkdir(parents=True, exist_ok=True)
    sdk_source = root / "tools/sunplus_sdk"
    for file in sdk_source.glob("*.py"):
        shutil.copy2(file, package / "lib/sunplus_sdk" / file.name)
    for name in ("README.md", "rebuild-tools.sh"):
        shutil.copy2(sdk_source / name, package / name)
    for name in ("examples", "patches"):
        shutil.copytree(sdk_source / name, package / name, dirs_exist_ok=True)
    for tool, directory in (("as218x", "as21"), ("ld21", "ld21")):
        shutil.copy2(args.tool_source / directory / tool, package / "bin" / tool)
    wrapper = package / "bin/sunplus-dsp"
    wrapper.write_text('''#!/usr/bin/env python3
from pathlib import Path
import os
import sys
root = Path(__file__).resolve().parents[1]
os.environ.setdefault("SUNPLUS_DSP_SDK_ROOT", str(root))
sys.path.insert(0, str(root / "lib"))
from sunplus_sdk.__main__ import main
main()
''')
    wrapper.chmod(0o755)
    tracked = subprocess.check_output(["git", "-C", str(args.upstream_repo), "ls-files", "-z"]).decode().split("\0")
    for relative in filter(None, tracked):
        source = args.tool_source / relative
        if not source.is_file():
            raise FileNotFoundError(source)
        destination = package / "source/open21xx" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    shutil.copy2(args.tool_source / "COPYING", package / "LICENSES/Open21xx-GPL-2.txt")
    shutil.copy2(root / "LICENSE", package / "LICENSES/GhidraMCP-Apache-2.txt")
    languages = root / "processors/SunplusSPHEAudioDSP/data/languages"
    language_source = package / "source/ghidra/languages"
    language_source.mkdir(parents=True)
    for suffix in ("slaspec", "pspec", "cspec", "ldefs"):
        shutil.copy2(languages / ("sunplus_sphe_audio_dsp." + suffix), language_source)
    java_sources = tuple(sorted((root / "src/main/java/com/xebyte/loaders").glob("SunplusDspElf*.java")))
    classes = output / "loader-classes"
    classes.mkdir()
    cp = os.pathsep.join(str(path) for path in args.ghidra.rglob("*.jar"))
    run([str(args.jdk / "bin/javac"), "-proc:none", "--release", "21", "-cp", cp,
         "-d", str(classes), *(str(path) for path in java_sources)])
    for source in java_sources:
        shutil.copy2(source, package / "source/ghidra" / source.name)
    jar = package / "ghidra/SunplusDspElfLoader.jar"
    jar_files = {str(path.relative_to(classes)): path.read_bytes() for path in classes.rglob("*.class")}
    jar_files["META-INF/MANIFEST.MF"] = b"Manifest-Version: 1.0\r\n\r\n"
    archive_zip(jar, jar_files)
    sla = output / "sunplus_sphe_audio_dsp.sla"
    run([str(args.ghidra / "support/sleigh"), str(language_source / "sunplus_sphe_audio_dsp.slaspec"), str(sla)])
    prefix = "SunplusDspSDK/"
    extension = {
        prefix + "extension.properties": b"name=SunplusDspSDK\ndescription=Experimental Sunplus DSP language and SDK ELF loader; not target acceptance\nauthor=RUSH project\ncreatedOn=2026-10-15\nversion=12.1.3\n",
        prefix + "Module.manifest": b"",
        prefix + "lib/SunplusDspElfLoader.jar": jar.read_bytes(),
        prefix + "LICENSE": (root / "LICENSE").read_bytes(),
        prefix + "README.md": (sdk_source / "README.md").read_bytes(),
        prefix + "data/languages/sunplus_sphe_audio_dsp.sla": sla.read_bytes(),
    }
    for path in language_source.iterdir():
        extension[prefix + "data/languages/" + path.name] = path.read_bytes()
    archive_zip(package / "ghidra/SunplusDspSDK-ghidra_12.1.3.zip", extension)
    manifest = {
        "version": "0.1-candidate", "platform": "linux-x86_64",
        "status": "ASSEMBLER_LINKER_AND_CONTAINER_TESTED; MODEL_RUNTIME_NOT_ACCEPTED",
        "ghidra": "12.1.3", "jdk": "21", "python_minimum": "3.10",
        "dynamic_dependencies": ["libelf.so.1", "libz.so.1", "libc.so.6"],
        "c_compiler_included": False, "canonical_model_migrated": False,
        "native_optimizer_patch_applied": False,
        "open21xx_revision": upstream,
        "files": {str(path.relative_to(package)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in sorted(package.rglob("*")) if path.is_file()},
    }
    (package / "sdk.json").write_text(json.dumps(manifest, indent=2) + "\n")
    archive = output / (package.name + ".tar.xz")
    with tarfile.open(archive, "x:xz") as tar:
        for path in sorted(package.rglob("*")):
            if not path.is_file():
                continue
            info = tar.gettarinfo(str(path), str(path.relative_to(output)))
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 1792022400
            with path.open("rb") as stream:
                tar.addfile(info, stream)
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            rel = Path(member.name).relative_to(package.name)
            assert tar.extractfile(member).read() == (package / rel).read_bytes()
    print("SDK_PACKAGE_BYTE_VERIFIED", archive, "bytes", archive.stat().st_size, flush=True)


if __name__ == "__main__":
    main()
