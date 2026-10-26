// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `Signature` enum + `KNOWN_COMPRESSION_SIGS` constant

#![forbid(unsafe_code)]

/// Compression / container magic byte sequences recognised by the
/// `VmlinuzDecompressor`.
///
/// Each variant carries the literal magic bytes that `Signature.check`
/// compares against.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Signature {
    /// `\x1f\x8b\x08` — gzip.
    CompressedGzip,
    /// `\xfd7zXZ\x00` — xz.
    CompressedXz,
    /// `]\x00\x00` — lzma.
    CompressedLzma,
    /// `m\x00\x00` — lzma alt.
    CompressedLzma6d,
    /// `BZh` — bzip2.
    CompressedBz2,
    /// `\x04"M\x18` — lz4 frame.
    CompressedLz4,
    /// `\x02!L\x18` — lz4 legacy.
    CompressedLz4Legacy,
    /// `(\xb5/\xfd` — zstd.
    CompressedZstd,
    /// `\x89LZ` — lzo.
    CompressedLzo,
    /// `UNCOMPRESSED_IMG` — Qualcomm patched-kernel magic.
    DtbAppendedQualcomm,
    /// `ANDROID!` — Android boot image.
    AndroidBootimg,
    /// `\x27\x05\x19\x56` — legacy U-Boot uImage.
    UImage,
}

impl Signature {
    /// Returns the magic bytes associated with this signature.
    #[must_use]
    pub const fn bytes(self) -> &'static [u8] {
        match self {
            Signature::CompressedGzip => &[0x1f, 0x8b, 0x08],
            Signature::CompressedXz => &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00],
            Signature::CompressedLzma => &[0x5d, 0x00, 0x00],
            Signature::CompressedLzma6d => &[0x6d, 0x00, 0x00],
            Signature::CompressedBz2 => &[0x42, 0x5a, 0x68],
            Signature::CompressedLz4 => &[0x04, 0x22, 0x4d, 0x18],
            Signature::CompressedLz4Legacy => &[0x02, 0x21, 0x4c, 0x18],
            Signature::CompressedZstd => &[0x28, 0xb5, 0x2f, 0xfd],
            Signature::CompressedLzo => &[0x89, 0x4c, 0x5a],
            Signature::DtbAppendedQualcomm => b"UNCOMPRESSED_IMG",
            Signature::AndroidBootimg => b"ANDROID!",
            Signature::UImage => &[0x27, 0x05, 0x19, 0x56],
        }
    }

    /// `Signature.check(data, offset, sign)`. Returns `true`
    /// iff `data[offset .. offset + sign.len()] == sign`.
    #[must_use]
    pub fn check(data: &[u8], offset: usize, sign: Signature) -> bool {
        let bytes = sign.bytes();
        if offset + bytes.len() > data.len() {
            return false;
        }
        data[offset..offset + bytes.len()] == *bytes
    }
}

/// `KNOWN_COMPRESSION_SIGS` constant.
pub const KNOWN_COMPRESSION_SIGS: &[Signature] = &[
    Signature::CompressedGzip,
    Signature::CompressedXz,
    Signature::CompressedLzma,
    Signature::CompressedLzma6d,
    Signature::CompressedBz2,
    Signature::CompressedLz4,
    Signature::CompressedLz4Legacy,
    Signature::CompressedZstd,
    Signature::CompressedLzo,
];
