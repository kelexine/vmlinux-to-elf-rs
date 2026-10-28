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
  (use `--no-default-features` on `v2e-db` to drop the `db` and `embedded` features).
- The full CLI needs a C compiler (bundled SQLite via `rusqlite`, and `liblzma`).
  Termux works natively (`pkg install clang`).

## Install

```bash
cargo install --git https://github.com/kelexine/vmlinux-to-elf-rs v2e-cli   # remote
cargo install --path crates/v2e-cli                                          # local checkout
```

No post-install step is needed: see the next section.

## Kernel database

`vmlinux-to-elf` and `kallsyms-finder` look the detected kernel version up in
the upstream project's database and log the kernel source/download links, the
release date, the architecture's interesting files, and a Debian build
environment from the same era. It only affects log output, never the ELF.

The 34 MB database is stored xz-compressed (1.78 MB) in
`crates/v2e-db/data/` and compiled into the binary (feature `embedded`, on by
default). On first use it is unpacked once to
`$XDG_DATA_HOME/vmlinux-to-elf/database-<version>.sqlite3`
(`~/.local/share/vmlinux-to-elf/` by default), so `cargo install` and a local
`cargo build` work with nothing to copy. Lookup order, first existing file wins:

1. `--db-path FILE` (a missing file is an error, never a silent fallback)
2. `V2E_DB_PATH`
3. `<exe dir>/database.sqlite3`, then `<exe dir>/../share/vmlinux-to-elf/database.sqlite3`
4. `<user data dir>/vmlinux-to-elf/database.sqlite3`
5. `/usr/local/share/vmlinux-to-elf/`, then `/usr/share/vmlinux-to-elf/`
6. `./database.sqlite3`
7. the embedded copy (unpacked once, falling back to the temp dir if the data dir is not writable)

`--no-db` skips the lookup. Provenance and regeneration of the asset:
[`crates/v2e-db/data/README.md`](crates/v2e-db/data/README.md).

## Workspace layout

```
crates/
├── v2e-elf        — hand-rolled ELF reader/writer (port of utils/elf.py)
├── v2e-arch       — architecture detection (port of core/architecture_detecter.py)
├── v2e-unpack     — compression + boot-image unpacker (port of core/auto_unpack.py)
├── v2e-kallsyms   — kallsyms locator + parser (port of core/kallsyms.py)
├── v2e-db         — optional kernel-version DB access (port of kernel_db/database.py)
└── v2e-cli        — four binaries (vmlinux-to-elf, kallsyms-finder, vmlinuz-decompressor, extract-ikconfig)
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
extract-ikconfig <kernel-image>
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
               [--db-path FILE | --no-db]
               INPUT_FILE OUTPUT_FILE
```

`kallsyms-finder` accepts `--db-path` / `--no-db` as well.

## Behavior differences from the Python tool

| # | Python | Rust | Reason |
|---|---|---|---|
| 1 | `vmlinuz-decompressor` exits 0 when no compression was recognized. | Exits **1**. | Conventional failure code. |
| 2 | Kernel DB opened with `db.connect()` at import time (peewee can create an empty file if it is missing). | Opened lazily and read-only; never creates a file. A missing database only drops the informational log lines. | Safer, and the DB never affects the ELF. |
| 3 | The 34 MB DB must sit next to the Python package. | Embedded xz-compressed (1.78 MB) and unpacked on first use; `--db-path`, `V2E_DB_PATH` and the standard share/data directories override it. | `cargo install` needs no post-install step. |
| 4 | Decompression candidate failures are swallowed silently. | `debug!`-level log per rejected candidate. | Easier debugging. |
| 5 | XZ codec via `liblzma` (C binding through Python's `lzma` module). | XZ codec via `xz2`/`liblzma` (C binding, documented exception). | Parity and speed. |
| 6 | LZO codec via `minilzo` (C binding). | Pure-Rust hand-written LZO1X-999 decoder. | No C dependency for this codec. |
| 7 | `pc_relative` v7.0+ heuristic uses hardcoded ELF offset assumption. | Faithfully ported (with doc-comment flag). | Behavior parity. |
| 8 | Malformed section alignment or sizes in an input ELF can misbehave. | Returns an `ElfError::LayoutOverflow` instead of wrapping. | Hostile-input safety. |
| 9 | Some informational log lines (decompression timings, `Architecture string`, `kallsyms_token_index` offset, relocation-range base guess, null-address percentage, `Reconstructing ELF…`). | Not printed. | Cosmetic; no effect on output. |

## Verification against the Python tool

Checked with Python `vmlinux-to-elf` 1.4.0 from PyPI on three real inputs: an
Ubuntu 6.8 x86-64 `vmlinuz`, an Android 4.19 aarch64 gzip kernel, and a 32 MB
Android `boot.img`. For every input the generated ELF, the `kallsyms-finder`
output (stdout and `--output`), the `vmlinuz-decompressor` output, and
`kallsyms-finder` run on the generated ELF are byte-identical. Error paths
(missing, empty, random, truncated-ELF and truncated-image inputs) exit with
the same status as Python. See `tests/differential/README.md` for the
procedure; it is not automated in CI because it needs the Python tool and
real kernel images.

## License

[GPL-3.0-or-later](LICENSE).

The Rust port is a derivative work of the original python tool by [Marin Moulinier](https://github.com/marin-m/vmlinux-to-elf), who retains attribution for the algorithms and design.