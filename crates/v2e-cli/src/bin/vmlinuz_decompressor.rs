// SPDX-License-Identifier: GPL-3.0-or-later

#![forbid(unsafe_code)]

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;
use v2e_cli::logging;
use v2e_unpack::VmlinuzDecompressor;

/// Utility to turn a compressed or packed kernel binary (with or without
/// a symbols table) into an raw uncompressed kernel binary.
#[derive(Parser, Debug)]
#[command(name = "vmlinuz-decompressor", version)]
struct Args {
    /// Path to the vmlinux/vmlinuz/zImage/bzImage/kernel.bin/kernel.elf
    /// file to decompress.
    input_file: PathBuf,
    /// Path to the decompressed file to output.
    output_file: PathBuf,
}

fn main() -> ExitCode {
    logging::init();
    let args = Args::parse();

    let compressed_data = match std::fs::read(&args.input_file) {
        Ok(b) => b,
        Err(e) => {
            log::error!("[!] Failed to read {}: {}", args.input_file.display(), e);
            return ExitCode::FAILURE;
        },
    };

    let decompressed = VmlinuzDecompressor::new(&compressed_data, true).decompressed;

    if compressed_data == decompressed {
        log::error!(
            "[!] No compressed or packed data was recognized within the given input kernel file"
        );
        return ExitCode::from(1);
    }

    if let Err(e) = std::fs::write(&args.output_file, &decompressed) {
        log::error!("[!] Failed to write {}: {}", args.output_file.display(), e);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
