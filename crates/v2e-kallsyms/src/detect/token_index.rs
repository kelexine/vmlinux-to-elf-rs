// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `find_kallsyms_token_index`. This step **also sets the
//! endianness**

#![forbid(unsafe_code)]

use crate::error::KallsymsError;

/// Result of `find_kallsyms_token_index`.
#[derive(Clone, Debug)]
pub struct TokenIndexResult {
    /// Absolute file offset where `kallsyms_token_index` begins.
    pub offset: usize,
    /// Absolute file offset immediately after the 256 × 2-byte index.
    pub end_offset: usize,
    /// Endianness decided by this step.
    pub is_big_endian: bool,
}

/// Token-table walker that returns the 256 byte-offsets of each
/// null-terminated token, starting at `token_table_offset`.
fn collect_token_offsets(
    kernel_img: &[u8],
    token_table_offset: usize,
) -> Result<(Vec<u16>, usize), KallsymsError> {
    let mut offsets: Vec<u16> = Vec::with_capacity(256);
    let mut position = token_table_offset;
    if position == 0 {
        position = 1;
    } else {
        position -= 1;
    }
    for _ in 0..256 {
        position += 1;
        offsets.push((position - token_table_offset) as u16);
        for _chars_in_token in 0..50 {
            position += 1;
            if position >= kernel_img.len() {
                return Err(KallsymsError::KallsymsNotFound);
            }
            if kernel_img[position] == 0 {
                break;
            }
        }
    }
    Ok((offsets, position))
}

/// Find `kallsyms_token_index`.
///
/// # Errors
/// Returns [`KallsymsError::TokenIndexNotFound`] if neither LE nor BE
/// serialization of the 256 offsets is found in the alignment window.
pub fn find_kallsyms_token_index(
    kernel_img: &[u8],
    token_table_offset: usize,
) -> Result<TokenIndexResult, KallsymsError> {
    let (offsets, position) = collect_token_offsets(kernel_img, token_table_offset)?;

    const MAX_ALIGNMENT: usize = 256;
    const KALLSYMS_TOKEN_INDEX_SIZE: usize = 256 * 2;

    let search_end = position + KALLSYMS_TOKEN_INDEX_SIZE + MAX_ALIGNMENT;
    if search_end > kernel_img.len() {
        return Err(KallsymsError::TokenIndexNotFound);
    }
    let memory = &kernel_img[position..search_end.min(kernel_img.len())];

    let le_bytes: Vec<u8> = offsets.iter().flat_map(|v| v.to_le_bytes()).collect();
    let be_bytes: Vec<u8> = offsets.iter().flat_map(|v| v.to_be_bytes()).collect();

    let le_pos = find_subsequence(memory, &le_bytes);
    let be_pos = find_subsequence(memory, &be_bytes);

    match (le_pos, be_pos) {
        (None, None) => Err(KallsymsError::TokenIndexNotFound),
        (Some(le), None) => Ok(TokenIndexResult {
            offset: position + le,
            end_offset: position + le + KALLSYMS_TOKEN_INDEX_SIZE,
            is_big_endian: false,
        }),
        (None, Some(be)) => Ok(TokenIndexResult {
            offset: position + be,
            end_offset: position + be + KALLSYMS_TOKEN_INDEX_SIZE,
            is_big_endian: true,
        }),
        (Some(le), Some(be)) => {
            if le > be {
                Ok(TokenIndexResult {
                    offset: position + le,
                    end_offset: position + le + KALLSYMS_TOKEN_INDEX_SIZE,
                    is_big_endian: false,
                })
            } else {
                Ok(TokenIndexResult {
                    offset: position + be,
                    end_offset: position + be + KALLSYMS_TOKEN_INDEX_SIZE,
                    is_big_endian: true,
                })
            }
        },
    }
}

#[inline]
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
