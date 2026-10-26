// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Legacy U-Boot uImage unpacker

#![forbid(unsafe_code)]

use crc32fast::Hasher;

/// Parsed legacy uImage header fields we need.
#[derive(Clone, Debug)]
pub struct UImageHeader {
    pub ih_magic: u32,
    pub ih_hcrc: u32,
    pub ih_time: u32,
    pub ih_size: u32,
    pub ih_load: u32,
    pub ih_ep: u32,
    pub ih_dcrc: u32,
    pub ih_os: u8,
    pub ih_arch: u8,
    pub ih_type: u8,
    pub ih_comp: u8,
    pub ih_name: [u8; 32],
}

/// Unpack a uImage at `offset`.
///
/// 1. Recursively try to decompress at `offset + 0x40` (skipping the
///    64-byte legacy header).
/// 2. If successful, rebuild a fixed-up uImage header with:
///    - `ih_comp` set to `IH_COMP_NONE = 0` (byte at offset 31).
///    - `ih_size` set to the decompressed data length (big-endian).
///    - `ih_dcrc` set to the CRC32 of the decompressed data.
///    - `ih_hcrc` reset to 0 then recomputed as CRC32 of the header.
/// 3. Return `header + decompressed_data`.
pub fn unpack(input: &[u8], offset: usize) -> Option<Vec<u8>> {
    // 1. Recurse.
    let decompressed =
        super::super::decompress::VmlinuzDecompressor::new(&input[offset + 0x40..], false);
    if decompressed.decompressed.is_empty() {
        return None;
    }
    let body = decompressed.decompressed;
    // 2. Build the patched header.
    let mut header = input[offset..offset + 0x40].to_vec();
    header[31] = 0; // ih_comp = NONE
    let body_size = body.len() as u32;
    header[12..16].copy_from_slice(&body_size.to_be_bytes()); // ih_size
    let dcrc = crc32(&body);
    header[24..28].copy_from_slice(&dcrc.to_be_bytes()); // ih_dcrc
    header[4..8].copy_from_slice(&[0u8; 4]); // ih_hcrc reset
    let hcrc = crc32(&header);
    header[4..8].copy_from_slice(&hcrc.to_be_bytes());
    // 3. Concatenate.
    let mut out = Vec::with_capacity(0x40 + body.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&body);
    Some(out)
}

#[inline]
fn crc32(data: &[u8]) -> u32 {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize()
}
