// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Error type for `v2e-kallsyms`.

#![forbid(unsafe_code)]

use thiserror::Error;

/// Top-level error returned by `KallsymsFinder` operations.
#[derive(Debug, Error)]
pub enum KallsymsError {
    /// `KallsymsNotFoundException` — no embedded symbol table found.
    #[error("No embedded symbol table found in this kernel")]
    KallsymsNotFound,

    /// `ArchitectureGuessError` propagated from `v2e-arch`.
    #[error("The architecture could not be guessed successfully")]
    ArchitectureGuess,

    /// No `Linux version X.Y.Z` string present in the input.
    #[error("No version string found in this kernel")]
    NoVersionString,

    /// Multiple kallsyms-token-table candidates and no way to disambiguate.
    #[error("{count} candidates for kallsyms_token_table in kernel image")]
    AmbiguousTokenTable {
        /// Number of candidates.
        count: usize,
    },

    /// kallsyms_token_index serialized bytes were not found within the
    /// expected alignment window.
    #[error("The value of kallsyms_token_index was not found")]
    TokenIndexNotFound,

    /// Could not guess the architecture register size from the OpenWRT
    /// uncompressed-markers chunk pattern.
    #[error("Could not guess the architecture register size for kernel")]
    UnknownRegisterSize,

    /// Could not find kallsyms_markers.
    #[error("Could not find kallsyms_markers")]
    MarkersNotFound,

    /// Could not find kallsyms_names.
    #[error("Could not find kallsyms_names")]
    NamesNotFound,

    /// Could not infer a consistent base address from the ARM64 RELA scan.
    #[error("Could not derive a consistent base from relocations")]
    RelocationBaseInconsistent,

    /// The RELA table would patch over the kallsyms region, which we refuse to do.
    #[error("relocation offset {r_offset:#x} overlaps kallsyms region")]
    RelocationWouldCorruptKallsyms {
        /// The offending relocation's `r_offset` value.
        r_offset: u64,
    },

    /// `utils/elf.py` parse/write failure.
    #[error("ELF error: {0}")]
    Elf(#[from] v2e_elf::error::ElfError),

    /// Cursor bounds-check failure.
    #[error("cursor read out of bounds: {0}")]
    Cursor(#[from] crate::cursor::CursorError),

    /// Catch-all for invariant violations that should be unreachable in
    /// practice; logged via the `Display` impl.
    #[error("internal invariant violated: {0}")]
    Internal(&'static str),
}

/// Convenience alias for the historical `KallsymsNotFoundException` name.
pub type KallsymsNotFoundException = KallsymsError;
