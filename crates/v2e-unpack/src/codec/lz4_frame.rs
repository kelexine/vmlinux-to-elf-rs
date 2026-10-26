// SPDX-License-Identifier: GPL-3.0-or-later
//
//! LZ4 frame decoder

#![forbid(unsafe_code)]

use lz4_flex::frame::FrameDecoder;
use std::io::Read;

pub fn decompress(input: &[u8]) -> Option<Vec<u8>> {
    let mut dec = FrameDecoder::new(input);
    let mut out = Vec::new();
    match dec.read_to_end(&mut out) {
        Ok(_) => Some(out),
        Err(_) => None,
    }
}
