// SPDX-License-Identifier: GPL-3.0-or-later
//
//! LZ4 legacy-frame decoder

#![forbid(unsafe_code)]

/// Maximum block size used by the legacy LZ4 frame format.
pub const MAX_LEGACY_BLOCK_SIZE: usize = 8 * 1024 * 1024;

/// Decompress an LZ4 legacy stream (magic `02 21 4C 18`).
///
/// Format:
///   4 bytes  : magic `0x184C2102`
///   for each block:
///     4 bytes : little-endian compressed block size
///     N bytes : compressed block data (decoded to ≤ 8 MB)
///   Loop ends when a 0-length block size is read, or the stream is
///   truncated, or the decompressed block is smaller than 8 MB.
pub fn decompress(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() < 4 {
        return None;
    }
    let magic = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    if magic != 0x0184C2102 {
        return None;
    }
    let mut pos = 4usize;
    let mut out: Vec<u8> = Vec::new();
    while pos + 4 <= input.len() {
        let block_size =
            u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]])
                as usize;
        pos += 4;
        if block_size == 0 || pos + block_size > input.len() {
            break;
        }
        let block = &input[pos..pos + block_size];
        pos += block_size;
        let decoded = lz4_flex::block::decompress(block, MAX_LEGACY_BLOCK_SIZE).ok()?;
        out.extend_from_slice(&decoded);
        if decoded.len() < MAX_LEGACY_BLOCK_SIZE {
            break;
        }
    }
    Some(out)
}
