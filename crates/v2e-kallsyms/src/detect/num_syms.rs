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
        let mut already_explored: Vec<i64> = vec![0; n];
        for unexplored in 0..n {
            let pos = markers_offset as i64 - unexplored as i64;
            if pos < 0 || pos as usize >= kernel_img.len() {
                already_explored[unexplored] = -1;
                continue;
            }
            let next_byte = kernel_img[pos as usize];
            let symbol_size: i64 = if next_byte & 0x80 != 0 {
                let hi = (next_byte & 0x7F) as i64;
                if pos as usize + 1 >= kernel_img.len() {
                    already_explored[unexplored] = -1;
                    continue;
                }
                let lo = kernel_img[pos as usize + 1] as i64;
                (hi | (lo << 7)) + 2
            } else {
                next_byte as i64 + 1
            };
            if next_byte == 0 {
                already_explored[unexplored] = if unexplored <= 256 { 0 } else { -1 };
            } else {
                let next_hop = unexplored as i64 - symbol_size;
                if next_hop < 0 || already_explored[next_hop as usize] == -1 {
                    already_explored[unexplored] = -1;
                } else {
                    already_explored[unexplored] = already_explored[next_hop as usize] + 1;
                }
            }
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
