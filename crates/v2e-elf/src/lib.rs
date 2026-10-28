// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `v2e-elf`
//!
//! A self-contained ELF reader/writer
//!
//! All public types are re-exported from this module.

#![forbid(unsafe_code)]
#![allow(missing_docs)]

pub mod endian;
pub mod enums;
pub mod error;
pub mod file;
pub mod header;
pub mod program;
pub mod section;

// Convenience re-exports.
pub use endian::{BitSize, Endianness};
pub use error::ElfError;
pub use file::{ElfFile, SectionLocator};
pub use header::{ELF_MAGIC, ELF32_HEADER_SIZE, ELF64_HEADER_SIZE, ElfFileHeader};
pub use program::{ELF32_PHDR_SIZE, ELF64_PHDR_SIZE, ElfProgramHeaderEntry};
pub use section::{
    ELF32_SHDR_SIZE, ELF64_SHDR_SIZE, ElfSection, ElfSectionHeader, ElfStrtab, RelocationEntry,
    SectionKind, SymbolEntry,
};

// Re-export enums for ergonomic access.
pub use enums::{EType, EiClass, EiData, EiOsabi, EiVersion, ShType, StInfoBinding, StInfoType};
pub use enums::{
    e_ident_indexes, p_flags, p_type, sh_flags, special_section_index, special_segment_index,
};
