// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `find_kallsyms_token_table`.

#![forbid(unsafe_code)]

use crate::error::KallsymsError;

/// Result of `find_kallsyms_token_table`.
#[derive(Clone, Debug)]
pub struct TokenTableResult {
    /// Absolute file offset where the token table begins.
    pub offset: usize,
}

/// Sequence to find: `0\01\0...9\0` (ASCII '0'..'9' each followed by NUL).
fn sequence_to_find() -> Vec<u8> {
    let mut v = Vec::with_capacity(20);
    for b in b'0'..=b'9' {
        v.push(b);
        v.push(0);
    }
    v
}

/// Sequences to avoid (immediately after the matched sequence).
const SEQUENCES_TO_AVOID: &[&[u8]] = &[b":\0", b"\0\0", b"\0\x01", b"\0\x02", b"ASCII\0"];

/// Find `kallsyms_token_table` in `kernel_img`.
///
/// # Errors
/// Returns [`KallsymsError::AmbiguousTokenTable`] on multiple candidates
/// with no way to disambiguate, or [`KallsymsError::KallsymsNotFound`]
/// when no candidate matches.
pub fn find_kallsyms_token_table(kernel_img: &[u8]) -> Result<TokenTableResult, KallsymsError> {
    let seq = sequence_to_find();
    let mut candidates: Vec<usize> = Vec::new();
    let mut candidates_alnum: Vec<usize> = Vec::new();

    let mut pos = 0usize;
    while pos + 1 < kernel_img.len() {
        let found = match find_subsequence(&kernel_img[pos..], &seq) {
            Some(p) => pos + p,
            None => break,
        };
        let after = found + seq.len();
        let mut avoided = false;
        for av in SEQUENCES_TO_AVOID {
            if after + av.len() <= kernel_img.len() && &kernel_img[after..after + av.len()] == *av {
                avoided = true;
                break;
            }
        }
        if !avoided {
            candidates.push(found);
            if after < kernel_img.len() && kernel_img[after].is_ascii_alphanumeric() {
                candidates_alnum.push(found);
            }
        }
        pos = found + 1;
    }

    if candidates.len() != 1 {
        if candidates_alnum.len() == 1 {
            candidates = candidates_alnum;
        } else if candidates.is_empty() {
            return Err(KallsymsError::KallsymsNotFound);
        } else {
            return Err(KallsymsError::AmbiguousTokenTable {
                count: candidates.len(),
            });
        }
    }

    let mut position = candidates[0];

    // Walk backward ord('0') = 48 tokens, each ≤ 50 chars.
    let start_idx = b'0' as usize;
    if position == 0 {
        return Err(KallsymsError::KallsymsNotFound);
    }
    position -= 1;
    if kernel_img[position] != 0 {
        return Err(KallsymsError::KallsymsNotFound);
    }
    for _token in 0..start_idx {
        let mut chars_in_token = 0usize;
        loop {
            if position == 0 {
                return Err(KallsymsError::KallsymsNotFound);
            }
            position -= 1;
            let b = kernel_img[position];
            if b == 0 || b > b'z' {
                break;
            }
            chars_in_token += 1;
            if chars_in_token >= 50 {
                return Err(KallsymsError::KallsymsNotFound);
            }
        }
    }
    position += 1;
    // 4-byte alignment (round down).
    position -= position % 4;

    log::info!(
        "[+] Found kallsyms_token_table at file offset 0x{:08x}",
        position
    );

    Ok(TokenTableResult { offset: position })
}

#[inline]
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
