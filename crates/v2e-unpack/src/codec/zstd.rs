// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Zstd decoder

#![forbid(unsafe_code)]

use ruzstd::decoding::StreamingDecoder;
use std::io::Read;

pub fn decompress(input: &[u8]) -> Option<Vec<u8>> {
    let mut dec = match StreamingDecoder::new(input) {
        Ok(d) => d,
        Err(_) => return None,
    };
    let mut out = Vec::new();
    match dec.read_to_end(&mut out) {
        Ok(_) => Some(out),
        Err(_) => None,
    }
}
