// SPDX-License-Identifier: GPL-3.0-or-later
//!
//! Detects and unpacks the kernel compression/boot-image formats:
//!
//! - gzip (single-member)
//! - xz
//! - lzma (legacy `]\x00\x00` and `m\x00\x00` variants)
//! - bzip2
//! - lz4 frame
//! - lz4 legacy
//! - zstd
//! - lzo (LZO1X-999 decoder)
//! - Android boot.img header versions 0, 1, 2, 3, 4
//! - uImage (legacy U-Boot)
//! - Qualcomm `UNCOMPRESSED_IMG` magic
//!
//! Module layout:
//!
//! ```text
//! v2e-unpack/
//! └── src/
//!     ├── lib.rs              // crate root, re-exports
//!     ├── signature.rs        // Signature enum, KNOWN_COMPRESSION_SIGS
//!     ├── decompress.rs       // VmlinuzDecompressor + DecompressOperation
//!     ├── boot/
//!     │   ├── mod.rs
//!     │   ├── android.rs      // Android boot.img v0–4
//!     │   ├── uimage.rs       // legacy uImage
//!     │   └── qualcomm.rs     // UNCOMPRESSED_IMG
//!     └── codec/
//!         ├── mod.rs
//!         ├── gzip.rs         // SingleGzipReader (one-member only)
//!         ├── xz.rs
//!         ├── lzma.rs         // incl. pylzma compat fallback
//!         ├── bzip2.rs
//!         ├── lz4_frame.rs
//!         ├── lz4_legacy.rs
//!         ├── zstd.rs
//!         └── lzo.rs          // pure-Rust LZO1X-999 decoder
//! ```

#![forbid(unsafe_code)]
#![allow(missing_docs)]

pub mod signature;
pub use signature::{Signature, KNOWN_COMPRESSION_SIGS};

pub mod decompress;
pub use decompress::{DecompressOperation, DecompressOperationType, VmlinuzDecompressor};

pub mod boot;
pub use boot::{AndroidBootImage, QualcommUncompressedImg, UImageHeader};

pub mod codec;
