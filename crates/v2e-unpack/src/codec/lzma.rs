// SPDX-License-Identifier: GPL-3.0-or-later
//
//! LZMA decoder

#![forbid(unsafe_code)]

/// Decompress an LZMA stream. Tries the raw format first; if that fails,
/// falls back to the pylzma format compatibility hack (insert 8 `0xFF`
/// bytes after the 5-byte LZMA header).
pub fn decompress(input: &[u8]) -> Option<Vec<u8>> {
    if let Some(out) = try_raw(input) {
        return Some(out);
    }
    if input.len() < 5 {
        return None;
    }
    let mut patched = Vec::with_capacity(input.len() + 8);
    patched.extend_from_slice(&input[..5]);
    patched.extend_from_slice(&[0xff; 8]);
    patched.extend_from_slice(&input[5..]);
    try_raw(&patched)
}

fn try_raw(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut cursor = std::io::Cursor::new(input);
    let res = lzma_rs::lzma_decompress(&mut cursor, &mut out);
    match res {
        Ok(_) => Some(out),
        Err(_) => None,
    }
}
