// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `VmlinuzDecompressor`

#![forbid(unsafe_code)]

use crate::boot;
use crate::codec;
use crate::signature::Signature;
use std::time::Instant;

/// Type of unpack/decompress operation.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum DecompressOperationType {
    /// Unpacking (Android bootimg / uImage / `UNCOMPRESSED_IMG`).
    Unpacking,
    /// Restoring (uImage header CRC rebuild).
    Restoring,
    /// Decompression (any compression codec).
    Decompression,
}

/// One decompress/unpack step.
#[derive(Clone, Debug)]
pub struct DecompressOperation {
    /// Operation type.
    pub op_type: DecompressOperationType,
    /// Signature that was matched.
    pub format_sig: Signature,
    /// Wall-clock seconds spent.
    pub op_time_secs: f64,
    /// Size of input buffer at the time of the step.
    pub src_size: usize,
    /// Absolute offset where the magic was found.
    pub src_offset: usize,
    /// Size of decompressed/unpacked output.
    pub dst_size: usize,
}

/// Main decompressor
pub struct VmlinuzDecompressor {
    /// Final decompressed output.
    pub decompressed: Vec<u8>,
    /// Every unpack/decompress step performed.
    pub operations_done: Vec<DecompressOperation>,
}

impl VmlinuzDecompressor {
    /// Construct and decompress
    #[must_use]
    pub fn new(input: &[u8], is_entry_point: bool) -> Self {
        let mut ops: Vec<DecompressOperation> = Vec::new();
        let out = Self::obtain_raw(input, is_entry_point, &mut ops);
        Self {
            decompressed: out,
            operations_done: ops,
        }
    }

    fn obtain_raw(buf: &[u8], is_entry_point: bool, ops: &mut Vec<DecompressOperation>) -> Vec<u8> {
        let mut current: Vec<u8> = buf.to_vec();
        loop {
            let file_size = current.len();

            // Build the set of candidate offsets to try.
            let mut offsets: Vec<usize> = vec![0];
            if file_size >= 80 {
                let tail = &current[file_size - 80..];
                // Last 20 u32 LE.
                for i in 0..20 {
                    let off = i * 4;
                    let v = u32::from_le_bytes([
                        tail[off],
                        tail[off + 1],
                        tail[off + 2],
                        tail[off + 3],
                    ]);
                    if (v as usize) < file_size {
                        offsets.push(v as usize);
                    }
                }
                // Last 20 u32 BE.
                for i in 0..20 {
                    let off = i * 4;
                    let v = u32::from_be_bytes([
                        tail[off],
                        tail[off + 1],
                        tail[off + 2],
                        tail[off + 3],
                    ]);
                    if (v as usize) < file_size {
                        offsets.push(v as usize);
                    }
                }
            }
            offsets.sort_unstable();
            offsets.dedup();

            // Try each offset.
            let mut found = false;
            for &off in &offsets {
                if let Some((decoded, op)) = Self::try_decompress_at(&current, off) {
                    if !decoded.is_empty()
                        && decoded.len() > 0x1000
                        && has_nul_in_first_32(&decoded)
                    {
                        ops.push(op);
                        current = decoded;
                        found = true;
                        break;
                    }
                }
            }

            if found {
                continue;
            }

            // Did we get something usable yet (Linux version string)?
            if find_linux_version(&current).is_some() {
                break;
            }

            // Scan-all-signatures fallback.
            for sig in crate::signature::KNOWN_COMPRESSION_SIGS {
                let mut search_from = 0usize;
                while search_from < current.len() {
                    let pos = match find_subsequence(&current, sig.bytes(), search_from) {
                        Some(p) => p,
                        None => break,
                    };
                    if let Some((decoded, op)) = Self::try_decompress_at(&current, pos) {
                        if !decoded.is_empty()
                            && decoded.len() > 0x1000
                            && has_nul_in_first_32(&decoded)
                        {
                            ops.push(op);
                            current = decoded;
                            found = true;
                            break;
                        }
                    }
                    search_from = pos + 1;
                }
                if found {
                    break;
                }
            }

            if !found {
                break;
            }
        }

        if !ops.is_empty() && is_entry_point {
            log::info!("[+] Kernel successfully decompressed or unpacked");
        } else if !ops.is_empty() {
            log::info!(
                "[+] Kernel successfully decompressed in-memory (the offsets that follow will be given relative to the decompressed binary)"
            );
        }
        current
    }

    /// Try to decompress/unpack at `offset`
    fn try_decompress_at(input: &[u8], offset: usize) -> Option<(Vec<u8>, DecompressOperation)> {
        let start = Instant::now();
        let src_size = input.len();
        let mut op = DecompressOperation {
            op_type: DecompressOperationType::Decompression,
            format_sig: Signature::CompressedGzip,
            op_time_secs: 0.0,
            src_size,
            src_offset: offset,
            dst_size: 0,
        };

        // Qualcomm UNCOMPRESSED_IMG
        if Signature::check(input, offset, Signature::DtbAppendedQualcomm) {
            op.op_type = DecompressOperationType::Unpacking;
            op.format_sig = Signature::DtbAppendedQualcomm;
            if let Some(out) = boot::qualcomm::unpack(input, offset) {
                op.op_time_secs = start.elapsed().as_secs_f64();
                op.dst_size = out.len();
                return Some((out, op));
            }
            return None;
        }

        // Android bootimg
        if Signature::check(input, offset, Signature::AndroidBootimg) && input.len() > 4096 {
            op.op_type = DecompressOperationType::Unpacking;
            op.format_sig = Signature::AndroidBootimg;
            if let Some(out) = boot::android::unpack(input, offset) {
                op.op_time_secs = start.elapsed().as_secs_f64();
                op.dst_size = out.len();
                // Recurse for nested UNCOMPRESSED_IMG.
                if let Some((nested, _)) = Self::try_decompress_at(&out, 0) {
                    return Some((nested, op));
                }
                return Some((out, op));
            }
            return None;
        }

        // uImage (legacy U-Boot) — only if ih_comp != NONE (byte at +0x1F != 0).
        if Signature::check(input, offset, Signature::UImage)
            && input.len() - offset > 64
            && input[offset + 31] != 0
        {
            if let Some(out) = boot::uimage::unpack(input, offset) {
                op.op_type = DecompressOperationType::Restoring;
                op.format_sig = Signature::UImage;
                op.op_time_secs = start.elapsed().as_secs_f64();
                op.dst_size = out.len();
                return Some((out, op));
            }
        }

        // Gzip
        if Signature::check(input, offset, Signature::CompressedGzip) {
            op.format_sig = Signature::CompressedGzip;
            if let Some(out) = codec::gzip::decompress_one_member(&input[offset..]) {
                op.op_time_secs = start.elapsed().as_secs_f64();
                op.dst_size = out.len();
                return Some((out, op));
            }
            return None;
        }

        // XZ
        if Signature::check(input, offset, Signature::CompressedXz) {
            op.format_sig = Signature::CompressedXz;
            if let Some(out) = codec::xz::decompress(&input[offset..]) {
                op.op_time_secs = start.elapsed().as_secs_f64();
                op.dst_size = out.len();
                return Some((out, op));
            }
            return None;
        }

        // LZMA (raw) — `]\x00\x00` or `m\x00\x00`
        if Signature::check(input, offset, Signature::CompressedLzma)
            || Signature::check(input, offset, Signature::CompressedLzma6d)
        {
            op.format_sig = Signature::CompressedLzma;
            if let Some(out) = codec::lzma::decompress(&input[offset..]) {
                op.op_time_secs = start.elapsed().as_secs_f64();
                op.dst_size = out.len();
                return Some((out, op));
            }
            return None;
        }

        // BZip2
        if Signature::check(input, offset, Signature::CompressedBz2) {
            op.format_sig = Signature::CompressedBz2;
            if let Some(out) = codec::bzip2::decompress(&input[offset..]) {
                op.op_time_secs = start.elapsed().as_secs_f64();
                op.dst_size = out.len();
                return Some((out, op));
            }
            return None;
        }

        // LZ4 frame
        if Signature::check(input, offset, Signature::CompressedLz4) {
            op.format_sig = Signature::CompressedLz4;
            if let Some(out) = codec::lz4_frame::decompress(&input[offset..]) {
                op.op_time_secs = start.elapsed().as_secs_f64();
                op.dst_size = out.len();
                return Some((out, op));
            }
            return None;
        }

        // LZ4 legacy
        if Signature::check(input, offset, Signature::CompressedLz4Legacy) {
            op.format_sig = Signature::CompressedLz4Legacy;
            if let Some(out) = codec::lz4_legacy::decompress(&input[offset..]) {
                op.op_time_secs = start.elapsed().as_secs_f64();
                op.dst_size = out.len();
                return Some((out, op));
            }
            return None;
        }

        // Zstd
        if Signature::check(input, offset, Signature::CompressedZstd) {
            op.format_sig = Signature::CompressedZstd;
            if let Some(out) = codec::zstd::decompress(&input[offset..]) {
                op.op_time_secs = start.elapsed().as_secs_f64();
                op.dst_size = out.len();
                return Some((out, op));
            }
            return None;
        }

        // LZO
        if Signature::check(input, offset, Signature::CompressedLzo) {
            op.format_sig = Signature::CompressedLzo;
            if let Some(out) = codec::lzo::decompress(&input[offset..]) {
                op.op_time_secs = start.elapsed().as_secs_f64();
                op.dst_size = out.len();
                return Some((out, op));
            }
            return None;
        }

        None
    }
}

#[inline]
fn has_nul_in_first_32(decoded: &[u8]) -> bool {
    decoded.iter().take(32).any(|&b| b == 0)
}

/// Find the byte offset of `needle` in `haystack`, starting at `from`.
/// Returns `None` if not found.
fn find_subsequence(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() + from {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Quick check for `Linux version X.Y.Z (...)` byte pattern.
fn find_linux_version(buf: &[u8]) -> Option<usize> {
    // We use a tiny byte search for the prefix; full regex lives in
    // v2e-kallsyms. This avoids a circular dependency.
    const PREFIX: &[u8] = b"Linux version ";
    find_subsequence(buf, PREFIX, 0)
}
