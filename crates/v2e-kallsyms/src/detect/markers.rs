// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `find_kallsyms_markers` (3-size long-type guess).

#![forbid(unsafe_code)]

use crate::error::KallsymsError;

/// Result of `find_kallsyms_markers`.
#[derive(Clone, Debug)]
pub struct MarkersResult {
    /// Absolute file offset where `kallsyms_markers` begins.
    pub offset: usize,
    /// Element size in bytes (2, 4, or 8).
    pub offset_table_element_size: usize,
}

/// Try element sizes 8, 4, 2
pub fn find_kallsyms_markers(
    kernel_img: &[u8],
    token_table_offset: usize,
    is_big_endian: bool,
) -> Result<MarkersResult, KallsymsError> {
    for &table_element_size in &[8usize, 4, 2] {
        let mut position = token_table_offset;
        let zeros = vec![0u8; table_element_size];
        // rfind pattern of `b'\x00' * table_element_size` up to 32 times.
        for _ in 0..32 {
            // Find the last occurrence of `zeros` in `kernel_img[0..position]`.
            let Some(rel) = rfind(kernel_img, &zeros, 0, position) else {
                break;
            };
            position = rel;
            position -= position % table_element_size;
            if position + table_element_size * 4 > kernel_img.len() {
                break;
            }
            let mut entries: [u64; 4] = [0; 4];
            for i in 0..4 {
                let off = position + i * table_element_size;
                entries[i] = read_uint(kernel_img, off, table_element_size, is_big_endian);
            }
            if entries[0] != 0 {
                continue;
            }
            let mut ok = true;
            for i in 1..4 {
                let prev = entries[i - 1];
                let curr = entries[i];
                if prev + 0x200 >= curr || prev + 0x40000 < curr {
                    ok = false;
                    break;
                }
            }
            if ok {
                log::info!(
                    "[+] Found kallsyms_markers at file offset 0x{:08x}",
                    position
                );
                return Ok(MarkersResult {
                    offset: position,
                    offset_table_element_size: table_element_size,
                });
            }
        }
    }
    Err(KallsymsError::MarkersNotFound)
}

#[inline]
fn rfind(haystack: &[u8], needle: &[u8], from: usize, to: usize) -> Option<usize> {
    if needle.is_empty() || to <= from || haystack.len() < needle.len() || to < needle.len() {
        return None;
    }
    let upper = to.min(haystack.len());
    if upper < needle.len() {
        return None;
    }
    let mut i = upper - needle.len();
    while i >= from {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    None
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
