// SPDX-License-Identifier: GPL-3.0-or-later
// Author: kelexine <https://github.com/kelexine>
// Date: 2026-10-28
//
//! Extraction of the embedded kernel `.config` (`CONFIG_IKCONFIG`).
//!
//! Port of the kernel's `scripts/extract-ikconfig` shell script: look for the
//! `IKCFG_ST` marker followed by a gzip stream in the image, and when that
//! fails, retry on the output of every candidate decompression found in it.
//! The script's `lzop` step is not ported: the `lzo` codec decodes raw
//! LZO1X, not the lzop container.

#![forbid(unsafe_code)]

use crate::codec;

/// Marker that precedes the gzip-compressed config inside the kernel.
const IKCFG_MARKER: &[u8] = b"IKCFG_ST";
/// Magic bytes of the gzip member that follows the marker.
const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b, 0x08];
/// Combined marker: IKCFG_ST + gzip header
const COMBINED_NEEDLE: &[u8] = b"IKCFG_ST\x1f\x8b\x08";

/// A compression format to try, with the decoder to run at each match.
struct Candidate {
    magic: &'static [u8],
    decode: fn(&[u8]) -> Option<Vec<u8>>,
}

/// Same formats, in the same order, as the shell script.
const CANDIDATES: &[Candidate] = &[
    Candidate {
        magic: GZIP_MAGIC,
        decode: codec::gzip::decompress_one_member,
    },
    Candidate {
        magic: &[0xfd, b'7', b'z', b'X', b'Z', 0x00],
        decode: codec::xz::decompress,
    },
    Candidate {
        magic: b"BZh",
        decode: codec::bzip2::decompress,
    },
    Candidate {
        magic: &[0x5d, 0x00, 0x00, 0x00],
        decode: codec::lzma::decompress,
    },
    Candidate {
        magic: &[0x02, 0x21, 0x4c, 0x18],
        decode: codec::lz4_legacy::decompress,
    },
];

/// Extract the kernel `.config` text from a kernel image, if present.
///
/// Returns `None` when the kernel was built without `CONFIG_IKCONFIG` (or
/// the image cannot be decoded).
#[must_use]
pub fn extract_ikconfig(image: &[u8]) -> Option<Vec<u8>> {
    if let Some(cfg) = dump_config(image) {
        return Some(cfg);
    }
    CANDIDATES.iter().find_map(|c| try_candidate(image, c))
}

/// Try the marker search on the decompressed output of every match of `c`.
fn try_candidate(image: &[u8], c: &Candidate) -> Option<Vec<u8>> {
    positions(image, c.magic)
        .filter_map(|pos| (c.decode)(&image[pos..]))
        .find_map(|decoded| dump_config(&decoded))
}

/// Look for `IKCFG_ST` + gzip magic in `data` and gunzip what follows.
fn dump_config(data: &[u8]) -> Option<Vec<u8>> {
    positions(data, COMBINED_NEEDLE).find_map(|pos| {
        let cfg = codec::gzip::decompress_one_member(&data[pos + IKCFG_MARKER.len()..])?;
        (!cfg.is_empty()).then_some(cfg)
    })
}

/// Every offset at which `needle` occurs in `haystack`.
fn positions<'a>(haystack: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(move |(i, w)| (w == needle).then_some(i))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    const CONFIG: &[u8] = b"CONFIG_IKCONFIG=y\nCONFIG_IKCONFIG_PROC=y\n";

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).expect("write to Vec cannot fail");
        enc.finish().expect("finish gzip")
    }

    fn image_with_config() -> Vec<u8> {
        let mut img = vec![0xAAu8; 256];
        img.extend_from_slice(IKCFG_MARKER);
        img.extend_from_slice(&gzip(CONFIG));
        img.extend_from_slice(b"MAGIC_END trailing bytes");
        img
    }

    #[test]
    fn finds_config_in_uncompressed_image() {
        assert_eq!(
            extract_ikconfig(&image_with_config()).as_deref(),
            Some(CONFIG)
        );
    }

    #[test]
    fn finds_config_in_gzipped_image() {
        let mut wrapped = vec![0x55u8; 64];
        wrapped.extend_from_slice(&gzip(&image_with_config()));
        assert_eq!(extract_ikconfig(&wrapped).as_deref(), Some(CONFIG));
    }

    #[test]
    fn returns_none_without_config() {
        assert!(extract_ikconfig(&[0u8; 1024]).is_none());
        assert!(extract_ikconfig(&gzip(b"no config in here")).is_none());
    }

    #[test]
    fn returns_none_for_empty_input() {
        assert!(extract_ikconfig(&[]).is_none());
    }
}
