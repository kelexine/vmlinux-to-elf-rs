// SPDX-License-Identifier: GPL-3.0-or-later
// Author: kelexine (https://github.com/kelexine)
// Rust port of marin-m/vmlinux-to-elf (https://github.com/marin-m/vmlinux-to-elf)
//
//! Behavioral tests for [`VmlinuzDecompressor`].

#![forbid(unsafe_code)]

use std::io::Write;
use v2e_unpack::VmlinuzDecompressor;

/// Marker the tests search for in the unpacked output.
const MARKER: &[u8] = b"Linux version 4.19.127 test";

/// Kernel-looking payload. The decompressor only accepts decoded data that is
/// larger than 4 KiB and has a NUL byte within its first 32 bytes, and nested
/// layers must each stay above 4 KiB after compression, so the body is
/// pseudo-random (deterministic LCG) rather than compressible text.
fn payload() -> Vec<u8> {
    let mut v = vec![0u8; 64];
    v.extend_from_slice(MARKER);
    let mut x: u32 = 0x1234_5678;
    for _ in 0..40_000 {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        v.push((x >> 24) as u8);
    }
    v
}

/// Length of the recognizable head (zeros + marker) used for containment checks.
const HEAD: usize = 64 + MARKER.len();

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn xz(data: &[u8]) -> Vec<u8> {
    let mut e = xz2::write::XzEncoder::new(Vec::new(), 6);
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn lz4_frame(data: &[u8]) -> Vec<u8> {
    let mut e = lz4_flex::frame::FrameEncoder::new(Vec::new());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn gzip_stream_is_unpacked() {
    let p = payload();
    let packed = gzip(&p);
    let out = VmlinuzDecompressor::new(&packed, true).decompressed;
    assert!(out != packed, "gzip data was left packed");
    assert!(contains(&out, &p[..HEAD]));
}

#[test]
fn xz_stream_is_unpacked() {
    let p = payload();
    let packed = xz(&p);
    let out = VmlinuzDecompressor::new(&packed, true).decompressed;
    assert!(out != packed, "xz data was left packed");
    assert!(contains(&out, &p[..HEAD]));
}

#[test]
fn lz4_frame_stream_is_unpacked() {
    let p = payload();
    let packed = lz4_frame(&p);
    let out = VmlinuzDecompressor::new(&packed, true).decompressed;
    assert!(out != packed, "lz4 data was left packed");
    assert!(contains(&out, &p[..HEAD]));
}

#[test]
fn compressed_data_after_a_junk_prefix_is_found() {
    let p = payload();
    let mut img = vec![0xAAu8; 1000];
    img.extend_from_slice(&gzip(&p));
    let out = VmlinuzDecompressor::new(&img, true).decompressed;
    assert!(
        contains(&out, &p[..HEAD]),
        "payload must be recovered from the middle of the image"
    );
}

#[test]
fn nested_compression_is_unpacked_recursively() {
    let p = payload();
    let packed = gzip(&xz(&p));
    let out = VmlinuzDecompressor::new(&packed, true).decompressed;
    assert!(contains(&out, &p[..HEAD]), "both layers must be removed");
}

#[test]
fn unrecognized_input_is_returned_unchanged() {
    let junk: Vec<u8> = (0..65_536u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let out = VmlinuzDecompressor::new(&junk, true).decompressed;
    assert_eq!(out, junk);
}

#[test]
fn empty_and_tiny_inputs_never_panic() {
    for input in [
        &b""[..],
        &b"\x1f"[..],
        &b"\x1f\x8b"[..],
        &b"\xfd7zXZ\x00"[..],
        &b"BZh"[..],
    ] {
        let out = VmlinuzDecompressor::new(input, true).decompressed;
        assert_eq!(out, input, "{input:?} must pass through untouched");
    }
}

#[test]
fn truncated_streams_never_panic() {
    let packed = gzip(&payload());
    for cut in [1, 2, 10, packed.len() / 2, packed.len() - 1] {
        let _ = VmlinuzDecompressor::new(&packed[..cut], true).decompressed;
    }
    let packed = xz(&payload());
    for cut in [1, 6, 12, packed.len() / 2, packed.len() - 1] {
        let _ = VmlinuzDecompressor::new(&packed[..cut], true).decompressed;
    }
}

#[test]
fn corrupted_stream_never_panics() {
    let mut packed = gzip(&payload());
    let mid = packed.len() / 2;
    packed[mid] ^= 0xFF;
    let _ = VmlinuzDecompressor::new(&packed, true).decompressed;
}
