// SPDX-License-Identifier: GPL-3.0-or-later
//
//! XZ decoder — uses `xz2` (liblzma, C binding).

#![forbid(unsafe_code)]

use std::io::Read;
use xz2::read::XzDecoder;

/// Decompress an XZ stream. Trailing data is discarded by the decoder.
pub fn decompress(input: &[u8]) -> Option<Vec<u8>> {
    let mut dec = XzDecoder::new(input);
    let mut out = Vec::new();
    match dec.read_to_end(&mut out) {
        Ok(_) => Some(out),
        Err(_) => None,
    }
}
