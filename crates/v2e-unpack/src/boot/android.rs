// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Android `boot.img` v0–4 unpacker

#![forbid(unsafe_code)]
#![allow(missing_docs)]

/// Parsed header bits we actually need.
#[derive(Clone, Debug)]
pub struct AndroidBootImage {
    pub header_version: u32,
    pub page_size: u32,
    pub kernel_size: u32,
    pub endianness: &'static str,
}

/// Unpack an Android boot image starting at `offset`. Returns the kernel
/// bytes on success, or `None` on any failure.
///
/// 1. Read `header_version` at `offset + 40` (LE) — fallback to BE.
/// 2. If `header_version ∈ {3, 4}` → `page_size = 4096`, use the endianness
///    inferred from step 1.
/// 3. Otherwise, read `page_size` at `offset + 36` (LE/BE), preferring
///    the smaller value if both are non-zero, falling back to BE.
/// 4. `kernel_size` is read at `offset + 8` in the chosen endianness.
/// 5. Validate sanity bounds, then return
///    `input[offset + page_size .. offset + page_size + kernel_size]`.
pub fn unpack(input: &[u8], offset: usize) -> Option<Vec<u8>> {
    if input.len() <= 4096 {
        return None;
    }
    if offset + 11 * 4 > input.len() {
        return None;
    }
    let hvr_le = u32::from_le_bytes([
        input[offset + 40],
        input[offset + 41],
        input[offset + 42],
        input[offset + 43],
    ]);
    let hvr_be = u32::from_be_bytes([
        input[offset + 40],
        input[offset + 41],
        input[offset + 42],
        input[offset + 43],
    ]);

    let (header_version, mut endianness): (u32, Option<&'static str>) = if hvr_le == hvr_be {
        (hvr_le, None)
    } else if hvr_le < 5 {
        (hvr_le, Some("little"))
    } else if hvr_be < 5 {
        (hvr_be, Some("big"))
    } else {
        return None;
    };

    let page_size: u32;
    if matches!(header_version, 3 | 4) {
        page_size = 4096;
        if endianness.is_none() {
            // Default to little-endian for v3/v4.
            endianness = Some("little");
        }
    } else {
        // Read page_size at offset + 36.
        let ps_le = u32::from_le_bytes([
            input[offset + 36],
            input[offset + 37],
            input[offset + 38],
            input[offset + 39],
        ]);
        let ps_be = u32::from_be_bytes([
            input[offset + 36],
            input[offset + 37],
            input[offset + 38],
            input[offset + 39],
        ]);
        match endianness {
            Some("little") => {
                page_size = ps_le;
            },
            Some("big") => {
                page_size = ps_be;
            },
            _ => {
                if ps_le < ps_be {
                    page_size = ps_le;
                    endianness = Some("little");
                } else {
                    page_size = ps_be;
                    endianness = Some("big");
                }
            },
        }
    }

    let endian_str = endianness?;
    let kernel_size = if endian_str == "little" {
        u32::from_le_bytes([
            input[offset + 8],
            input[offset + 9],
            input[offset + 10],
            input[offset + 11],
        ])
    } else {
        u32::from_be_bytes([
            input[offset + 8],
            input[offset + 9],
            input[offset + 10],
            input[offset + 11],
        ])
    };

    if kernel_size <= 0x1000 || (kernel_size as usize) >= input.len() {
        return None;
    }
    if page_size <= 0x200 || (page_size as usize) >= input.len() {
        return None;
    }
    let start = offset + page_size as usize;
    let end = start + kernel_size as usize;
    if end > input.len() {
        return None;
    }
    Some(input[start..end].to_vec())
}
