// SPDX-License-Identifier: GPL-3.0-or-later
//
//! BZip2 decoder

#![forbid(unsafe_code)]

use bzip2_rs::DecoderReader;
use std::io::Read;

pub fn decompress(input: &[u8]) -> Option<Vec<u8>> {
    let mut dec = DecoderReader::new(input);
    let mut out = Vec::new();
    match dec.read_to_end(&mut out) {
        Ok(_) => Some(out),
        Err(_) => None,
    }
}
