# Benchmark results

Rust port vs the Python reference (`vmlinux-to-elf` 1.4.0 from PyPI), measured
with [hyperfine](https://github.com/sharkdp/hyperfine) 1.19.0 through
`tests/perf/bench.sh`.

Reproduce:

```sh
cargo build --release
python3 -m venv venv && venv/bin/pip install vmlinux-to-elf
PY_BIN=$PWD/venv/bin tests/perf/bench.sh path/to/vmlinuz path/to/boot.img
```
Logging: the default level is `info` (the same messages as the Python tool).
Set `RUST_LOG=debug` for more, including how long each detection stage took
(`[~] architecture detection: 0.205 s`). Benchmarks: [`benches/RESULTS.md`](benches/RESULTS.md).


## Current numbers

Mean of 3 runs, wall clock. Machine: single-core Intel Xeon @ 2.10 GHz VM
(shared sandbox), so treat absolute times as indicative and the ratios as the
useful part. The two tools do the same work and produce byte-identical output
on these inputs (see `tests/differential/`).

| Input | Tool | Rust | Python | Rust is |
|---|---|---|---|---|
| Ubuntu 6.8 x86-64 `vmlinuz` (15 MB) | `vmlinux-to-elf` | 1.70 s | 61.79 s | 36x faster |
| | `kallsyms-finder` | 1.94 s | 6.15 s | 3.2x faster |
| Android 4.19 `boot.img` v2.9 (33.5 MB) | `vmlinux-to-elf` | 0.94 s | 41.99 s | 44x faster |
| | `kallsyms-finder` | 0.89 s | 5.65 s | 6.3x faster |
| Android 4.19 stock kernel (11 MB, gzip) | `vmlinux-to-elf` | 0.88 s (±0.57) | 17.73 s | 20x faster |
| | `kallsyms-finder` | 0.51 s | 3.63 s | 7.2x faster |

The ± on the last `vmlinux-to-elf` row is large because that run used no
warm-up and its first Rust run was a cold-cache read.

## What the first benchmark found

The first round (same machine) showed the port losing on `kallsyms-finder` for
the x86-64 kernel (Rust 7.30 s vs Python 5.20 s) and barely winning on
`boot.img` (1.1x). Per-stage timings (`RUST_LOG=debug`) pointed at three
stages, all fixed:

| Stage (Ubuntu 6.8, 71 MB image) | Before | After | Cause |
|---|---|---|---|
| `kallsyms_num_syms` search | 3.89 s | 0.03 s | The DP table was rebuilt from scratch on every 4-byte step back; the reference extends one table across retries. |
| Architecture detection | 1.51 s | 0.21 s | Two patterns started with a wildcard and were tried at every byte; patterns now jump between candidates with a vectorized byte search. |
| Kernel version search | 1.00 s | 0.004 s | The `regex` crate ran without its `perf` feature and in Unicode mode, so the literal `Linux version ` prefix was not used as a prefilter. |

Before the fixes: `vmlinux-to-elf` was 7.7x / 8.1x / 10.7x faster on the three
inputs above and `kallsyms-finder` 0.7x / 1.1x / 1.8x.

## Seeing where time goes

```sh
RUST_LOG=debug kallsyms-finder IMAGE 2>&1 >/dev/null | grep -E '^\[~\].* s$'
```

prints one line per detection stage.

## Caveats

* Three runs per command; Python timings drifted by up to ~10% between
  sessions on this shared VM.
* Only x86-64 and aarch64 images were benchmarked.
* Rust times include the one-time unpack of the embedded kernel database on the
  very first run on a machine (about a 34 MB write); steady-state runs reuse it.
