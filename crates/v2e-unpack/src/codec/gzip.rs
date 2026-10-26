// SPDX-License-Identifier: GPL-3.0-or-later
//
//! GZip decoder

#![forbid(unsafe_code)]

use flate2::read::GzDecoder;
use std::io::Read;

/// Decompress exactly one GZip member. Trailing data (appended DTB,
/// concatenated streams) is discarded.
pub fn decompress_one_member(input: &[u8]) -> Option<Vec<u8>> {
    let mut dec = GzDecoder::new(input);
    let mut out = Vec::new();
    match dec.read_to_end(&mut out) {
        Ok(_) => Some(out),
        Err(_) => None,
    }
}
