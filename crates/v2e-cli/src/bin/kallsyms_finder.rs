// SPDX-License-Identifier: GPL-3.0-or-later

#![forbid(unsafe_code)]

use clap::Parser;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use v2e_cli::logging;
use v2e_kallsyms::{KallsymsFinder, KallsymsFinderConfig};
use v2e_unpack::VmlinuzDecompressor;

/// Find the kernel's embedded symbol table from a raw or stripped ELF
/// kernel file, and print these to the standard output with their
/// addresses or optionally save them to a file.
#[derive(Parser, Debug)]
#[command(name = "kallsyms-finder", version)]
struct Args {
    /// Path to the kernel file to extract symbols from.
    input_file: PathBuf,
    /// Path to the analyzable .kallsyms output.
    #[arg(long = "output")]
    output: Option<PathBuf>,
    /// Assume kallsyms offsets are absolute addresses.
    #[arg(long = "use-absolute")]
    use_absolute: bool,
    /// Force overriding the input kernel bit size, providing 32 or 64
    /// bit (rather than auto-detect).
    #[arg(long = "bit-size")]
    bit_size: Option<u32>,
    /// Force overriding the base address used for converting relocations
    /// to relative relocations with this integer value (rather than
    /// auto-detect).
    #[arg(long = "base-address", value_name = "HEX_NUMBER")]
    base_address: Option<u64>,
}

fn main() -> ExitCode {
    logging::init();
    let args = Args::parse();

    let raw_input = match std::fs::read(&args.input_file) {
        Ok(b) => b,
        Err(e) => {
            log::error!("[!] Failed to read {}: {}", args.input_file.display(), e);
            return ExitCode::FAILURE;
        },
    };

    let decompressed = VmlinuzDecompressor::new(&raw_input, false).decompressed;

    let cfg = KallsymsFinderConfig {
        bit_size: args.bit_size,
        override_relative_base: args.use_absolute,
        explicit_base_address: args.base_address,
    };

    let finder = match KallsymsFinder::new(decompressed, cfg) {
        Ok(f) => f,
        Err(e) => {
            log::error!("[!] kallsyms extraction failed: {e}");
            return ExitCode::FAILURE;
        },
    };

    let mut stdout = std::io::stdout().lock();
    let _ = finder.print_symbols_debug(&mut stdout);
    let _ = stdout.flush();

    if let Some(out_path) = args.output {
        let path = if out_path.extension().and_then(|e| e.to_str()) == Some("kallsyms") {
            out_path
        } else {
            let mut p = out_path.clone().into_os_string();
            p.push(".kallsyms");
            PathBuf::from(p)
        };
        let mut file = match std::fs::File::create(&path) {
            Ok(f) => f,
            Err(e) => {
                log::error!("[!] Failed to create {}: {}", path.display(), e);
                return ExitCode::FAILURE;
            },
        };
        let _ = finder.print_symbols_debug(&mut file);
    }

    ExitCode::SUCCESS
}
