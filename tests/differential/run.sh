#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Author: kelexine (https://github.com/kelexine)
#
# Differential test: run the Python reference tool and this Rust port on the
# same kernel images and compare their outputs byte for byte.
#
# Usage:
#   tests/differential/run.sh IMAGE [IMAGE...]
#
# Environment:
#   PY_BIN   directory holding the Python console scripts
#            (default: $(dirname "$(command -v vmlinux-to-elf)"))
#   RS_BIN   directory holding the Rust binaries (default: target/release)
#   OUT      scratch directory for outputs (default: a fresh mktemp -d)
#
# Setup for the reference tool:
#   python3 -m venv venv && venv/bin/pip install vmlinux-to-elf
#   PY_BIN=$PWD/venv/bin tests/differential/run.sh path/to/vmlinuz path/to/boot.img
#
# Compared per image: generated ELF, kallsyms-finder stdout, kallsyms-finder
# --output, vmlinuz-decompressor output, and kallsyms-finder run on the
# generated ELF. Exit status is non-zero if anything differs.

set -u

if [ "$#" -eq 0 ]; then
    echo "usage: $0 IMAGE [IMAGE...]" >&2
    exit 2
fi

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
RS_BIN=${RS_BIN:-$ROOT/target/release}
PY_BIN=${PY_BIN:-$(dirname "$(command -v vmlinux-to-elf 2>/dev/null || echo /nonexistent/x)")}
OUT=${OUT:-$(mktemp -d)}

for tool in vmlinux-to-elf kallsyms-finder vmlinuz-decompressor; do
    for dir in "$PY_BIN" "$RS_BIN"; do
        if [ ! -x "$dir/$tool" ]; then
            echo "missing $dir/$tool (set PY_BIN / RS_BIN, and run 'cargo build --release')" >&2
            exit 2
        fi
    done
done

mkdir -p "$OUT"
failures=0

report() { # report LABEL FILE_A FILE_B -> prints one result line, counts differences
    if cmp -s "$2" "$3"; then
        printf '  %-26s IDENTICAL\n' "$1"
    else
        printf '  %-26s DIFF\n' "$1"
        failures=$((failures + 1))
    fi
}

for image in "$@"; do
    name=$(basename "$image" | tr -c 'A-Za-z0-9._-' '_')
    echo "== $image"

    "$PY_BIN/vmlinux-to-elf" "$image" "$OUT/$name.py.elf" >/dev/null 2>&1
    "$RS_BIN/vmlinux-to-elf" "$image" "$OUT/$name.rs.elf" >/dev/null 2>&1
    report "vmlinux-to-elf" "$OUT/$name.py.elf" "$OUT/$name.rs.elf"

    "$PY_BIN/kallsyms-finder" "$image" >"$OUT/$name.kf.py" 2>/dev/null
    "$RS_BIN/kallsyms-finder" "$image" >"$OUT/$name.kf.rs" 2>/dev/null
    report "kallsyms-finder" "$OUT/$name.kf.py" "$OUT/$name.kf.rs"

    "$PY_BIN/kallsyms-finder" "$image" --output "$OUT/$name.ko.py" >/dev/null 2>&1
    "$RS_BIN/kallsyms-finder" "$image" --output "$OUT/$name.ko.rs" >/dev/null 2>&1
    report "kallsyms-finder --output" "$OUT/$name.ko.py.kallsyms" "$OUT/$name.ko.rs.kallsyms"

    "$PY_BIN/vmlinuz-decompressor" "$image" "$OUT/$name.dc.py" >/dev/null 2>&1
    "$RS_BIN/vmlinuz-decompressor" "$image" "$OUT/$name.dc.rs" >/dev/null 2>&1
    report "vmlinuz-decompressor" "$OUT/$name.dc.py" "$OUT/$name.dc.rs"

    "$PY_BIN/kallsyms-finder" "$OUT/$name.py.elf" >"$OUT/$name.kfe.py" 2>/dev/null
    "$RS_BIN/kallsyms-finder" "$OUT/$name.py.elf" >"$OUT/$name.kfe.rs" 2>/dev/null
    report "kallsyms-finder on ELF" "$OUT/$name.kfe.py" "$OUT/$name.kfe.rs"
done

echo
if [ "$failures" -eq 0 ]; then
    echo "all outputs identical (scratch files in $OUT)"
else
    echo "$failures comparison(s) differ (scratch files in $OUT)" >&2
    exit 1
fi
