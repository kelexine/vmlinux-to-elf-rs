// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Error type for v2e-elf.

#![forbid(unsafe_code)]

use thiserror::Error;

/// Error returned by any `v2e-elf` operation that fails to parse or
/// serialize an ELF structure.
#[derive(Debug, Error)]
pub enum ElfError {
    /// Input too short for the requested ELF structure.
    #[error("unexpected end of ELF input (needed {needed} bytes at offset {offset})")]
    Truncated {
        /// Absolute byte offset where the read started.
        offset: usize,
        /// Number of bytes that were required.
        needed: usize,
    },

    /// The EI_CLASS / EI_DATA byte did not match a known value.
    #[error("invalid ELF identification byte {byte:#x} at offset {offset}")]
    InvalidIdent {
        /// Absolute byte offset of the offending byte.
        offset: usize,
        /// The byte value that was found.
        byte: u8,
    },

    /// A section index was out of range for `e_shnum`.
    #[error("section index {index} out of range (e_shnum={shnum})")]
    SectionIndex {
        /// The offending section index.
        index: usize,
        /// Total number of sections declared in the file header.
        shnum: usize,
    },

    /// Attempted to serialize an ElfFile that has no SHF_ALLOC section.
    #[error("this ELF object does not have a section with SH_ALLOC flag")]
    NoAllocSection,

    /// Generic wrapper for I/O failures (rare; used only when serializing
    /// into a writer that itself fails).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
