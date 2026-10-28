// SPDX-License-Identifier: GPL-3.0-or-later
// Author: kelexine <https://github.com/kelexine>
// Date: 2026-10-28
//
// Port of the kernel's `scripts/extract-ikconfig`.

#![forbid(unsafe_code)]

use clap::Parser;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use v2e_unpack::ikconfig::extract_ikconfig;

/// Exit status for a missing/empty input file, as in the original script.
const EXIT_USAGE: u8 = 2;

/// Extract the .config file from a kernel image.
///
/// This only works when the kernel was compiled with CONFIG_IKCONFIG.
#[derive(Parser, Debug)]
#[command(name = "extract-ikconfig", version)]
struct Args {
    /// Path to the kernel image (raw, or compressed with gzip, xz, bzip2,
    /// lzma or lz4).
    kernel_image: PathBuf,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let image = match std::fs::read(&args.kernel_image) {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => {
            eprintln!("extract-ikconfig: {} is empty", args.kernel_image.display());
            return ExitCode::from(EXIT_USAGE);
        },
        Err(e) => {
            eprintln!(
                "extract-ikconfig: cannot read {}: {e}",
                args.kernel_image.display()
            );
            return ExitCode::from(EXIT_USAGE);
        },
    };

    let Some(config) = extract_ikconfig(&image) else {
        eprintln!("extract-ikconfig: Cannot find kernel config.");
        return ExitCode::FAILURE;
    };

    if let Err(e) = std::io::stdout().lock().write_all(&config) {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            eprintln!("extract-ikconfig: failed to write config: {e}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
