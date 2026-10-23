#!/bin/sh
set -eu
SDK=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$#" -ne 1 ]; then echo "Usage: $0 NEW_BUILD_DIRECTORY" >&2; exit 2; fi
if [ -e "$1" ]; then echo 'Build directory already exists; refusing overwrite' >&2; exit 2; fi
mkdir -p -- "$1"
OUT=$(CDPATH= cd -- "$1" && pwd)
cp -R "$SDK/source/open21xx" "$OUT/source"
make -C "$OUT/source/libas21"
make -C "$OUT/source/as21" as218x
make -C "$OUT/source/ld21" YACC=bison
mkdir "$OUT/bin"
cp "$OUT/source/as21/as218x" "$OUT/source/ld21/ld21" "$OUT/bin/"
printf 'Built: %s/bin\n' "$OUT"
