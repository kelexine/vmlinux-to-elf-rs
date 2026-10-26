// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Compression codecs

#![forbid(unsafe_code)]

pub mod bzip2;
pub mod gzip;
pub mod lz4_frame;
pub mod lz4_legacy;
pub mod lzma;
pub mod lzo;
pub mod xz;
pub mod zstd;
