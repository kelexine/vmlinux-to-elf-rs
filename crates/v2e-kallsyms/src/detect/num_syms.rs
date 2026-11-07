// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `find_kallsyms_num_syms`.

#![forbid(unsafe_code)]

use crate::error::KallsymsError;

/// Result of `find_kallsyms_num_syms`.
#[derive(Clone, Debug)]
pub struct NumSymsResult {
    /// Absolute file offset of the `num_syms` integer.
    pub offset: usize,
    /// Decoded symbol count.
    pub num_symbols: usize,
}

/// Find `kallsyms_num_syms`.
///
/// # Errors
/// Returns [`KallsymsError::NamesNotFound`] on failure.
pub fn find_kallsyms_num_syms(
    kernel_img: &[u8],
    names_offset: usize,
    markers_offset: usize,
    tokens: &[String],
    is_big_endian: bool,
    offset_table_element_size: usize,
) -> Result<(NumSymsResult, usize), KallsymsError> {
    let possible_symbol_types: Vec<char> = vec![
        'A', 'B', 'D', 'R', 'T', 'V', 'W', 'G', 'I', 'N', 'P', 'C', 'S', 'U', 'u', 'v', 'w', '-',
        '?',
    ];

    let mut names_offset = names_offset;
    let max_alignment = 256usize;

    // `already_explored[k]` is the number of symbol entries reachable when
    // starting `k` bytes before `kallsyms_markers` (-1 if invalid). It depends
    // only on `k` and the image bytes, never on `names_offset`, so it is kept
    // across retries and only extended: rebuilding it on every 4-byte step back
    // made this stage quadratic (seconds on a 70 MB kernel).
    let mut already_explored: Vec<i64> = Vec::new();

    loop {
        if names_offset + 1 >= kernel_img.len() {
            return Err(KallsymsError::NamesNotFound);
        }
        let first_token_index = kernel_img[names_offset + 1] as usize;
        if first_token_index >= tokens.len() {
            // skip backward
            if names_offset < 4 {
                return Err(KallsymsError::NamesNotFound);
            }
            names_offset -= 4;
            continue;
        }
        let first_token = &tokens[first_token_index];
        let first_char = first_token.chars().next().unwrap_or('?');
        let first_lower = first_char.to_ascii_lowercase();
        let is_symbol_type = possible_symbol_types.contains(&first_char)
            || possible_symbol_types.contains(&first_lower.to_ascii_uppercase())
            || matches!(first_lower, 'u' | 'v' | 'w');
        if !is_symbol_type {
            if names_offset < 4 {
                return Err(KallsymsError::NamesNotFound);
            }
            names_offset -= 4;
            continue;
        }

        // DP backward count.
        let n = markers_offset as i64 - names_offset as i64 + 1;
        if n <= 0 {
            return Err(KallsymsError::NamesNotFound);
        }
        let n = n as usize;
        already_explored.reserve(n.saturating_sub(already_explored.len()));
        for unexplored in already_explored.len()..n {
            let value = explore_one(kernel_img, markers_offset, unexplored, &already_explored);
            already_explored.push(value);
        }
        let num_symbols = already_explored[n - 1];
        if num_symbols < 256 {
            if names_offset < 4 {
                return Err(KallsymsError::NamesNotFound);
            }
            names_offset -= 4;
            continue;
        }

        // Find the encoded num_syms within MAX_ALIGNMENT bytes before names.
        let encoded = encode_uint(num_symbols as u64, offset_table_element_size, is_big_endian);
        let search_start = names_offset.saturating_sub(max_alignment + 20);
        let search_end = names_offset;
        let needle = match rfind(kernel_img, &encoded, search_start, search_end) {
            Some(p) => p,
            None => {
                if names_offset < 4 {
                    return Err(KallsymsError::NamesNotFound);
                }
                names_offset -= 4;
                continue;
            },
        };
        log::info!(
            "[+] Found kallsyms_names at file offset 0x{:08x} ({} symbols)",
            names_offset,
            num_symbols
        );
        log::info!(
            "[+] Found kallsyms_num_syms at file offset 0x{:08x}",
            needle
        );
        return Ok((
            NumSymsResult {
                offset: needle,
                num_symbols: num_symbols as usize,
            },
            names_offset,
        ));
    }
}

/// DP value for the entry that starts `unexplored` bytes before
/// `markers_offset`: how many symbol entries follow it up to the terminating
/// zero-size entry, or `-1` when the walk would leave the image, overrun the
/// markers, or the terminator is implausibly far (> 256 bytes from the end).
///
/// `explored` holds the values for all smaller distances.
fn explore_one(
    kernel_img: &[u8],
    markers_offset: usize,
    unexplored: usize,
    explored: &[i64],
) -> i64 {
    let Some(pos) = markers_offset.checked_sub(unexplored) else {
        return -1;
    };
    let Some(&next_byte) = kernel_img.get(pos) else {
        return -1;
    };
    let symbol_size: i64 = if next_byte & 0x80 != 0 {
        let Some(&lo) = kernel_img.get(pos + 1) else {
            return -1;
        };
        (i64::from(next_byte & 0x7F) | (i64::from(lo) << 7)) + 2
    } else {
        i64::from(next_byte) + 1
    };
    if next_byte == 0 {
        // Last entry of the table.
        return if unexplored <= 256 { 0 } else { -1 };
    }
    let next_hop = unexplored as i64 - symbol_size;
    if next_hop < 0 {
        return -1;
    }
    match explored.get(next_hop as usize) {
        Some(&previous) if previous != -1 => previous + 1,
        _ => -1,
    }
}

#[inline]
fn rfind(haystack: &[u8], needle: &[u8], from: usize, to: usize) -> Option<usize> {
    if needle.is_empty() || to <= from || to < needle.len() {
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
fn encode_uint(v: u64, size: usize, big_endian: bool) -> Vec<u8> {
    match size {
        2 => {
            let b = (v as u16).to_ne_bytes();
            if big_endian {
                (v as u16).to_be_bytes().to_vec()
            } else {
                (v as u16).to_le_bytes().to_vec()
            }
        },
        4 => {
            if big_endian {
                (v as u32).to_be_bytes().to_vec()
            } else {
                (v as u32).to_le_bytes().to_vec()
            }
        },
        8 => {
            if big_endian {
                v.to_be_bytes().to_vec()
            } else {
                v.to_le_bytes().to_vec()
            }
        },
        _ => Vec::new(),
    }
}
