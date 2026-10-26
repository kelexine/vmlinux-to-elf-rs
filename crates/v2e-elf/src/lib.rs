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
pub use file::ElfFile;
pub use header::{ElfFileHeader, ELF32_HEADER_SIZE, ELF64_HEADER_SIZE, ELF_MAGIC};
pub use program::{ElfProgramHeaderEntry, ELF32_PHDR_SIZE, ELF64_PHDR_SIZE};
pub use section::{
    ElfSection, ElfSectionHeader, ElfStrtab, RelocationEntry, SectionKind, SymbolEntry,
    ELF32_SHDR_SIZE, ELF64_SHDR_SIZE,
};

// Re-export enums for ergonomic access.
pub use enums::{
    e_ident_indexes, p_flags, p_type, sh_flags, special_section_index, special_segment_index,
};
pub use enums::{EType, EiClass, EiData, EiOsabi, EiVersion, ShType, StInfoBinding, StInfoType};
