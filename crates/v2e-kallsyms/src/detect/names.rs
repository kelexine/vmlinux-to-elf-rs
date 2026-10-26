// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `find_kallsyms_names`. Approximates the position based on the
//! last entry of `kallsyms_markers`.

#![forbid(unsafe_code)]

use crate::error::KallsymsError;

/// Result of `find_kallsyms_names`.
#[derive(Clone, Debug)]
pub struct NamesResult {
    /// Absolute file offset where `kallsyms_names` begins (approximate).
    pub offset: usize,
}

/// Approximate `kallsyms_names` position by reading the last meaningful
/// entry from `kallsyms_markers` and subtracting it from the markers offset.
pub fn find_kallsyms_names(
    kernel_img: &[u8],
    markers: &crate::detect::markers::MarkersResult,
    token_table_offset: usize,
    is_big_endian: bool,
) -> Result<NamesResult, KallsymsError> {
    let elem = markers.offset_table_element_size;
    let max_entries = (token_table_offset - markers.offset) / elem;
    let count = max_entries.min(3000);

    let mut entries: Vec<u64> = Vec::with_capacity(count);
    for i in 0..count {
        let off = markers.offset + i * elem;
        entries.push(read_uint(kernel_img, off, elem, is_big_endian));
    }

    // Truncate at the first non-monotonic entry.
    let mut end = entries.len();
    for i in 1..entries.len() {
        let prev = entries[i - 1];
        let curr = entries[i];
        if prev + 0x200 >= curr || prev + 0x40000 < curr {
            end = i;
            break;
        }
    }
    entries.truncate(end);
    let last_nonzero = entries
        .iter()
        .copied()
        .filter(|&v| v != 0)
        .last()
        .unwrap_or(0);

    let position = markers.offset as i64 - last_nonzero as i64;
    if position <= 0 {
        return Err(KallsymsError::NamesNotFound);
    }
    // Round up to element alignment.
    let pos = position as usize;
    let pos = pos + ((elem - (pos % elem)) % elem);
    Ok(NamesResult { offset: pos })
}

#[inline]
fn read_uint(data: &[u8], off: usize, size: usize, big_endian: bool) -> u64 {
    if off + size > data.len() {
        return 0;
    }
    match size {
        2 => {
            let b = &data[off..off + 2];
            if big_endian {
                u16::from_be_bytes([b[0], b[1]]) as u64
            } else {
                u16::from_le_bytes([b[0], b[1]]) as u64
            }
        },
        4 => {
            let b = &data[off..off + 4];
            if big_endian {
                u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64
            } else {
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64
            }
        },
        8 => {
            let b = &data[off..off + 8];
            if big_endian {
                u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            } else {
                u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            }
        },
        _ => 0,
    }
}
