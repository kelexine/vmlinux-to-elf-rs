// SPDX-License-Identifier: GPL-3.0-or-later

#![forbid(unsafe_code)]

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;
use v2e_cli::logging;
use v2e_kallsyms::{KallsymsFinder, KallsymsFinderConfig};
use v2e_unpack::VmlinuzDecompressor;

/// Turn a raw or compressed kernel binary, or a kernel ELF without
/// symbols, into a fully analyzable ELF whose symbols were extracted
/// from the kernel symbol table.
#[derive(Parser, Debug)]
#[command(name = "vmlinux-to-elf", version)]
struct Args {
    /// Path to the vmlinux/vmlinuz/zImage/bzImage/kernel.bin/kernel.elf
    /// file to make into an analyzable .ELF.
    input_file: PathBuf,
    /// Path to the analyzable .ELF to output.
    output_file: PathBuf,
    /// Force overriding the output ELF "e_machine" field with this
    /// integer value (rather than auto-detect).
    #[arg(long = "e-machine", value_name = "DECIMAL_NUMBER")]
    e_machine: Option<u32>,
    /// Force overriding the input kernel bit size, providing 32 or 64
    /// bit (rather than auto-detect).
    #[arg(long = "bit-size", value_name = "BIT_SIZE")]
    bit_size: Option<u32>,
    /// Consider that the raw kernel starts at this offset of the
    /// provided raw file or compressed stream (rather than 0, or the
    /// beginning of the ELF sections if an ELF header was present in
    /// the input).
    #[arg(long = "file-offset", value_name = "HEX_NUMBER")]
    file_offset: Option<u64>,
    /// Force overriding the output ELF base address field with this
    /// integer value (rather than auto-detect).
    #[arg(long = "base-address", value_name = "HEX_NUMBER")]
    base_address: Option<u64>,
    /// Size in megabytes of the .bss section in the binary.
    #[arg(long = "bss-size", default_value_t = 16)]
    bss_size: u32,
    /// Assume kallsyms offsets are absolute addresses.
    #[arg(long = "use-absolute")]
    use_absolute: bool,
    /// Use this kernel database file instead of searching the standard
    /// locations (the `V2E_DB_PATH` environment variable works too).
    #[arg(long = "db-path", value_name = "FILE", conflicts_with = "no_db")]
    db_path: Option<PathBuf>,
    /// Skip the kernel database lookup (source links, build environment).
    #[arg(long = "no-db")]
    no_db: bool,
}

fn main() -> ExitCode {
    logging::init();
    let args = Args::parse();

    if (args.e_machine.is_some()) ^ (args.bit_size.is_some()) {
        log::error!(
            "[!] Please specify both an addressing bit size and the ELF \"e_machine\" field, or neither for auto-detection"
        );
        return ExitCode::FAILURE;
    }

    let raw_input = match std::fs::read(&args.input_file) {
        Ok(b) => b,
        Err(e) => {
            log::error!("[!] Failed to read {}: {}", args.input_file.display(), e);
            return ExitCode::FAILURE;
        },
    };

    let decompressed = VmlinuzDecompressor::new(&raw_input, false).decompressed;

    let file_contents = if let Some(off) = args.file_offset {
        if (off as usize) >= decompressed.len() {
            log::error!("[!] --file-offset past end of decompressed buffer");
            return ExitCode::FAILURE;
        }
        decompressed[off as usize..].to_vec()
    } else {
        decompressed
    };

    let db = match v2e_cli::db::open_kernel_db(args.db_path.as_deref(), args.no_db) {
        Ok(db) => db,
        Err(e) => {
            log::error!("[!] {e}");
            return ExitCode::FAILURE;
        },
    };

    let cfg = KallsymsFinderConfig {
        bit_size: args.bit_size,
        override_relative_base: args.use_absolute,
        explicit_base_address: args.base_address,
        db,
    };

    let finder = match KallsymsFinder::new(file_contents.clone(), cfg) {
        Ok(f) => f,
        Err(e) => {
            log::error!("[!] kallsyms extraction failed: {e}");
            return ExitCode::FAILURE;
        },
    };

    // Build output ELF.
    let elf = match v2e_cli::symbolizer::build_elf(
        &file_contents,
        &finder,
        args.e_machine,
        args.bit_size,
        args.base_address,
        args.bss_size,
    ) {
        Ok(e) => e,
        Err(e) => {
            log::error!("[!] ELF symbolization failed: {e}");
            return ExitCode::FAILURE;
        },
    };

    let mut out: Vec<u8> = Vec::with_capacity(file_contents.len() + 0x10000);
    if let Err(e) = elf.serialize(&mut out) {
        log::error!("[!] ELF serialize failed: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = std::fs::write(&args.output_file, &out) {
        log::error!("[!] Failed to write {}: {}", args.output_file.display(), e);
        return ExitCode::FAILURE;
    }
    log::info!(
        "[+] Successfully wrote the new ELF kernel to {}",
        args.output_file.display()
    );

    ExitCode::SUCCESS
}
