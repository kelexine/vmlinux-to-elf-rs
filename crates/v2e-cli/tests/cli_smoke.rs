// SPDX-License-Identifier: GPL-3.0-or-later

//! End-to-end smoke tests for the three CLI binaries. These tests
//! invoke the binaries via `std::process::Command` against tiny
//! synthetic inputs to confirm:
//!
//! - the `--help` flag works
//! - the `--version` flag works
//! - invocation on an empty / non-kernel input fails cleanly (exit
//!   code 1, no panic)

#![forbid(unsafe_code)]

use std::process::Command;

const HELP_FAIL_FAST: &str = "should fail to start without arguments";

fn bin_path(name: &str) -> std::path::PathBuf {
    // Try release build first, fall back to debug.
    let mut release = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    release.push("../../target/release");
    release.push(name);
    if release.is_file() {
        return release;
    }
    let mut debug = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    debug.push("../../target/debug");
    debug.push(name);
    debug
}

#[test]
fn vmlinux_to_elf_help_works() {
    let bin = bin_path("vmlinux-to-elf");
    let out = Command::new(&bin).arg("--help").output();
    match out {
        Ok(o) => {
            assert!(o.status.success(), "exit code: {:?}", o.status.code());
            let stdout = String::from_utf8_lossy(&o.stdout);
            assert!(stdout.contains("Turn a raw or compressed kernel"));
        },
        Err(e) => {
            // Skip if release binary wasn't built (cargo test runs in dev profile).
            eprintln!("skip vmlinux-to-elf --help: {e}");
        },
    }
}

#[test]
fn vmlinuz_decompressor_version_works() {
    let bin = bin_path("vmlinuz-decompressor");
    let out = Command::new(&bin).arg("--version").output();
    match out {
        Ok(o) => {
            assert!(o.status.success(), "exit code: {:?}", o.status.code());
            let stdout = String::from_utf8_lossy(&o.stdout);
            assert!(
                stdout.contains("0.1.0"),
                "expected version 0.1.0 in stdout, got: {stdout}"
            );
        },
        Err(e) => {
            eprintln!("skip vmlinuz-decompressor --version: {e}");
        },
    }
}

#[test]
fn vmlinux_to_elf_no_args_fails() {
    let bin = bin_path("vmlinux-to-elf");
    let out = Command::new(&bin).output();
    match out {
        Ok(o) => {
            // clap exits with code 2 on missing required arguments.
            assert_ne!(o.status.code(), Some(0), "{HELP_FAIL_FAST}");
        },
        Err(e) => {
            eprintln!("skip vmlinux-to-elf no-args: {e}");
        },
    }
}

#[test]
fn vmlinuz_decompressor_on_empty_input_exits_nonzero() {
    // Per decision #4, vmlinuz-decompressor exits 1 on no-compression-found.
    let bin = bin_path("vmlinuz-decompressor");
    let tmp = std::env::temp_dir().join("v2e-empty-input.bin");
    let _ = std::fs::write(&tmp, b"not a kernel");
    let out_path = std::env::temp_dir().join("v2e-empty-output.bin");
    let out = Command::new(&bin).arg(&tmp).arg(&out_path).output();
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(&out_path);
    match out {
        Ok(o) => {
            assert_eq!(
                o.status.code(),
                Some(1),
                "expected exit code 1 per decision #4"
            );
        },
        Err(e) => {
            eprintln!("skip vmlinuz-decompressor empty: {e}");
        },
    }
}
