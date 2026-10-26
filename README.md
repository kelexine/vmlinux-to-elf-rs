# vmlinux-to-elf-rs — Rust port of marin-m/vmlinux-to-elf

A faithful, memory-safe Rust port of [`marin-m/vmlinux-to-elf`](https://github.com/marin-m/vmlinux-to-elf).

> Takes a raw or compressed Linux kernel image (`vmlinux`, `vmlinuz`,
> `bzImage`, `zImage`, Android `Image` / `boot.img`), unpacks it, finds the
> embedded `kallsyms` table, infers architecture / endianness / bit size /
> entry point / base address, and writes a fully analyzable `.ELF` with
> recovered symbols.


## Toolchain

- MSRV: **1.90.0**.
- Targets: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`.
- The library crates (`v2e-elf`, `v2e-arch`, `v2e-unpack`, `v2e-kallsyms`)
  cross-compile to `aarch64-unknown-linux-gnu` without a C toolchain
  (use `--no-default-features` to drop the `db` feature).
## Workspace layout

```
crates/
├── v2e-elf        — hand-rolled ELF reader/writer (port of utils/elf.py)
├── v2e-arch       — architecture detection (port of core/architecture_detecter.py)
├── v2e-unpack     — compression + boot-image unpacker (port of core/auto_unpack.py)
├── v2e-kallsyms   — kallsyms locator + parser (port of core/kallsyms.py)
├── v2e-db         — optional kernel-version DB access (port of kernel_db/database.py)
└── v2e-cli        — three binaries (vmlinux-to-elf, kallsyms-finder, vmlinuz-decompressor)
tests/
├── fixtures/
│   └── elf_tests/   — the 6 ELF fixtures shipped with the original Python tool
└── differential/
    └── README.md   — manual Python-vs-Rust comparison procedure
```

## Build & test

```bash
cargo build --release           # build all 3 binaries
cargo test                      # run unit + integration tests
cargo fmt --check               # verify formatting
cargo clippy --workspace --all-targets -- -D warnings
```

## CLI usage

```
vmlinux-to-elf <input_kernel.bin> <output_kernel.elf>
kallsyms-finder <input_kernel.bin> [--output FOO]
vmlinuz-decompressor <input_kernel.bin> <output_kernel.bin>
```

All three binaries accept `-V`/`--version` and `-h`/`--help`.

The full set of `vmlinux-to-elf` flags (matching the Python `argparse`
definitions verbatim):

```
vmlinux-to-elf [--e-machine DECIMAL_NUMBER]
               [--bit-size BIT_SIZE]
               [--file-offset HEX_NUMBER]
               [--base-address HEX_NUMBER]
               [--bss-size BSS_SIZE]
               [--use-absolute]
               INPUT_FILE OUTPUT_FILE
```

## Behavior differences from the Python tool

| # | Python | Rust | Reason |
|---|---|---|---|
| 1 | `vmlinuz-decompressor` exits 0 when no compression was recognized. | Exits **1**. | Conventional failure code. |
| 2 | Kernel DB always loaded at import time, `db.connect()` may write an empty DB if file is missing. | DB loaded lazily, opened read-only, **silent skip** when absent. |
| 4 | Decompression candidate failures are swallowed silently. | `debug!`-level log per rejected candidate. |
| 5 | XZ codec via `liblzma` (C binding through Python's `lzma` module). | XZ codec via `xz2`/`liblzma` (C binding, documented exception). |
| 6 | LZO codec via `minilzo` (C binding). | Pure-Rust hand-written LZO1X-999 decoder. |
| 7 | `pc_relative` v7.0+ heuristic uses hardcoded ELF offset assumption. | Faithfully ported (with doc-comment flag). |

## License

[GPL-3.0-or-later](LICENSE).

The Rust port is a derivative work of the original python tool by [Marin Moulinier](https://github.com/marin-m/vmlinux-to-elf), who retains attribution for the algorithms and design.