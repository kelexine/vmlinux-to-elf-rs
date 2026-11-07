#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Author: kelexine (https://github.com/kelexine)
#
# Benchmark the Rust port against the Python reference with hyperfine.
#
# Usage:
#   tests/perf/bench.sh IMAGE [IMAGE...]
#
# Environment:
#   PY_BIN    directory with the Python console scripts
#             (default: $(dirname "$(command -v vmlinux-to-elf)"))
#   RS_BIN    directory with the Rust binaries (default: target/release)
#   OUT       directory for the exported results (default: benches/)
#   WARMUP    warm-up runs before measuring (default: 1)
#   MIN_RUNS  minimum measured runs per command (default: 3)
#   MAX_RUNS  maximum measured runs per command (default: 10)
#
# What is measured, per image:
#   vmlinux-to-elf    full pipeline: unpack, find kallsyms, write the ELF
#   kallsyms-finder   unpack + symbol recovery, symbols written with --output
#                     (hyperfine discards stdout)
#
# The kernel database lookup is part of the default Rust run (as it is for the
# Python tool), so these numbers are what a user sees. Results are exported as
# Markdown and JSON per image/tool.
#
# Run on an otherwise idle machine: the numbers are wall-clock times.

set -eu

if [ "$#" -eq 0 ]; then
    echo "usage: $0 IMAGE [IMAGE...]" >&2
    exit 2
fi

if ! command -v hyperfine >/dev/null 2>&1; then
    echo "hyperfine not found (https://github.com/sharkdp/hyperfine)" >&2
    exit 2
fi

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
RS_BIN=${RS_BIN:-$ROOT/target/release}
PY_BIN=${PY_BIN:-$(dirname "$(command -v vmlinux-to-elf 2>/dev/null || echo /nonexistent/x)")}
OUT=${OUT:-$ROOT/benches}
WARMUP=${WARMUP:-1}
MIN_RUNS=${MIN_RUNS:-3}
MAX_RUNS=${MAX_RUNS:-10}

for tool in vmlinux-to-elf kallsyms-finder; do
    for dir in "$PY_BIN" "$RS_BIN"; do
        if [ ! -x "$dir/$tool" ]; then
            echo "missing $dir/$tool (set PY_BIN / RS_BIN, and run 'cargo build --release')" >&2
            exit 2
        fi
    done
done

mkdir -p "$OUT"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

for image in "$@"; do
    name=$(basename "$image" | tr -c 'A-Za-z0-9._-' '_')
    size=$(wc -c <"$image" | tr -d ' ')
    echo "== $image ($size bytes)"

    # -N: run the commands directly, without an intermediate shell, so the
    # measurement does not include shell start-up.
    hyperfine -N --warmup "$WARMUP" --min-runs "$MIN_RUNS" --max-runs "$MAX_RUNS" \
        --export-markdown "$OUT/$name.vmlinux-to-elf.md" \
        --export-json "$OUT/$name.vmlinux-to-elf.json" \
        -n "rust   vmlinux-to-elf" "$RS_BIN/vmlinux-to-elf $image $scratch/rs.elf" \
        -n "python vmlinux-to-elf" "$PY_BIN/vmlinux-to-elf $image $scratch/py.elf"

    # kallsyms-finder prints ~100k lines; -N has no shell, so use --output
    # into the scratch directory for both tools instead of a redirect.
    hyperfine -N --warmup "$WARMUP" --min-runs "$MIN_RUNS" --max-runs "$MAX_RUNS" \
        --export-markdown "$OUT/$name.kallsyms-finder.md" \
        --export-json "$OUT/$name.kallsyms-finder.json" \
        -n "rust   kallsyms-finder" "$RS_BIN/kallsyms-finder $image --output $scratch/rs.kf" \
        -n "python kallsyms-finder" "$PY_BIN/kallsyms-finder $image --output $scratch/py.kf"
done

echo
echo "results exported to $OUT"
