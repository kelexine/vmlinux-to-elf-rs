// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Qualcomm `UNCOMPRESSED_IMG` unpacker

#![forbid(unsafe_code)]

/// Unpack a Qualcomm-patched kernel file that begins with the
/// `UNCOMPRESSED_IMG` magic. The 16 bytes after the magic are reserved,
/// and the next 4 bytes are a little-endian DTB offset. The kernel body
/// is `min(dtb_offset_le, dtb_offset_be)` bytes after the 20-byte
/// preamble.
pub fn unpack(input: &[u8], offset: usize) -> Option<Vec<u8>> {
    let magic = b"UNCOMPRESSED_IMG";
    if input.len() < offset + magic.len() + 20 {
        return None;
    }
    let off16 = offset + 16;
    if off16 + 4 > input.len() {
        return None;
    }
    let dtb_le = u32::from_le_bytes([
        input[off16],
        input[off16 + 1],
        input[off16 + 2],
        input[off16 + 3],
    ]);
    let dtb_be = u32::from_be_bytes([
        input[off16],
        input[off16 + 1],
        input[off16 + 2],
        input[off16 + 3],
    ]);
    let limit = dtb_le.min(dtb_be) as usize;
    let body_start = offset + 20;
    if body_start + limit > input.len() {
        return None;
    }
    Some(input[body_start..body_start + limit].to_vec())
}

/// Marker for the Qualcomm `UNCOMPRESSED_IMG` magic.
pub struct QualcommUncompressedImg;
