// SPDX-License-Identifier: GPL-3.0-or-later
// Author: kelexine (https://github.com/kelexine)
// Rust port of marin-m/vmlinux-to-elf (https://github.com/marin-m/vmlinux-to-elf)
//
//! Robustness tests for [`ArchitectureDetector`]: it parses untrusted binaries,
//! so it must never panic and must report "unknown" instead of guessing.

#![forbid(unsafe_code)]

use v2e_arch::{ArchitectureDetector, LinuxArm64EfiStub};

#[test]
fn empty_input_is_an_error() {
    assert!(ArchitectureDetector::guess(&[]).is_err());
}

#[test]
fn all_zero_input_is_not_misdetected() {
    assert!(ArchitectureDetector::guess(&[0u8; 4096]).is_err());
}

#[test]
fn tiny_inputs_never_panic() {
    for len in 0..64usize {
        let buf: Vec<u8> = (0..len).map(|i| (i * 37) as u8).collect();
        let _ = ArchitectureDetector::guess(&buf);
    }
}

#[test]
fn pseudo_random_inputs_never_panic() {
    let mut x: u32 = 0xDEAD_BEEF;
    for size in [1usize, 7, 255, 4096, 65_536, 300_000] {
        let buf: Vec<u8> = (0..size)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (x >> 24) as u8
            })
            .collect();
        let _ = ArchitectureDetector::guess(&buf);
    }
}

#[test]
fn efi_stub_parser_rejects_garbage_without_panicking() {
    assert!(LinuxArm64EfiStub::parse(&[]).is_none());
    assert!(LinuxArm64EfiStub::parse(&[0xFF; 3]).is_none());
    assert!(LinuxArm64EfiStub::parse(&vec![0xFF; 4096]).is_none());
    // "MZ" header with truncated PE offsets must not read out of bounds.
    let mut mz = vec![0u8; 64];
    mz[0] = b'M';
    mz[1] = b'Z';
    mz[0x3c..0x40].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    assert!(LinuxArm64EfiStub::parse(&mz).is_none());
}
