// SPDX-License-Identifier: GPL-3.0-or-later
//
//! ELF program-header entry.

#![forbid(unsafe_code)]

use crate::endian::{BitSize, Endianness};
use crate::error::ElfError;
use crate::header::{parse_u16, parse_u32, parse_u64, ser_u16, ser_u32, ser_u64};
use std::io::Write;

/// On-disk size of `Elf32_Phdr`.
pub const ELF32_PHDR_SIZE: usize = 32;
/// On-disk size of `Elf64_Phdr`.
pub const ELF64_PHDR_SIZE: usize = 56;

/// A program-header entry (covers both ELF32 and ELF64 layouts).
#[derive(Clone, Debug)]
pub struct ElfProgramHeaderEntry {
    /// `p_type`.
    pub p_type: u32,
    /// `p_offset`.
    pub p_offset: u64,
    /// `p_vaddr`.
    pub p_vaddr: u64,
    /// `p_paddr`.
    pub p_paddr: u64,
    /// `p_filesz`.
    pub p_filesz: u64,
    /// `p_memsz`.
    pub p_memsz: u64,
    /// `p_flags`.
    pub p_flags: u32,
    /// `p_align`.
    pub p_align: u64,
}

impl ElfProgramHeaderEntry {
    /// Construct a fresh entry with all fields zeroed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            p_type: 0,
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0,
            p_memsz: 0,
            p_flags: 0,
            p_align: 0,
        }
    }

    /// On-disk entry size.
    #[must_use]
    pub const fn entry_size(bits: BitSize) -> usize {
        match bits {
            BitSize::Bits32 => ELF32_PHDR_SIZE,
            BitSize::Bits64 => ELF64_PHDR_SIZE,
        }
    }

    /// Parse one entry.
    ///
    /// # Errors
    /// Returns [`ElfError::Truncated`] if `data` is too short.
    pub fn parse(
        data: &[u8],
        offset: usize,
        endian: Endianness,
        bits: BitSize,
    ) -> Result<Self, ElfError> {
        let need = Self::entry_size(bits);
        if data.len() < offset + need {
            return Err(ElfError::Truncated {
                offset,
                needed: need,
            });
        }
        let be = matches!(endian, Endianness::Big);
        Ok(match bits {
            BitSize::Bits32 => {
                let p_type = parse_u32(data, offset, be);
                let p_offset = parse_u32(data, offset + 4, be) as u64;
                let p_vaddr = parse_u32(data, offset + 8, be) as u64;
                let p_paddr = parse_u32(data, offset + 12, be) as u64;
                let p_filesz = parse_u32(data, offset + 16, be) as u64;
                let p_memsz = parse_u32(data, offset + 20, be) as u64;
                let p_flags = parse_u32(data, offset + 24, be);
                let p_align = parse_u32(data, offset + 28, be) as u64;
                Self {
                    p_type,
                    p_offset,
                    p_vaddr,
                    p_paddr,
                    p_filesz,
                    p_memsz,
                    p_flags,
                    p_align,
                }
            },
            BitSize::Bits64 => {
                let p_type = parse_u32(data, offset, be);
                let p_flags = parse_u32(data, offset + 4, be);
                let p_offset = parse_u64(data, offset + 8, be);
                let p_vaddr = parse_u64(data, offset + 16, be);
                let p_paddr = parse_u64(data, offset + 24, be);
                let p_filesz = parse_u64(data, offset + 32, be);
                let p_memsz = parse_u64(data, offset + 40, be);
                let p_align = parse_u64(data, offset + 48, be);
                Self {
                    p_type,
                    p_offset,
                    p_vaddr,
                    p_paddr,
                    p_filesz,
                    p_memsz,
                    p_flags,
                    p_align,
                }
            },
        })
    }

    /// Serialize one entry.
    ///
    /// # Errors
    /// Returns [`ElfError::Io`] only on writer failure.
    pub fn serialize<W: Write>(
        &self,
        out: &mut W,
        endian: Endianness,
        bits: BitSize,
    ) -> Result<(), ElfError> {
        let be = matches!(endian, Endianness::Big);
        let mut buf: Vec<u8> = Vec::with_capacity(Self::entry_size(bits));
        match bits {
            BitSize::Bits32 => {
                buf.extend_from_slice(&ser_u32(self.p_type, be));
                buf.extend_from_slice(&ser_u32(self.p_offset as u32, be));
                buf.extend_from_slice(&ser_u32(self.p_vaddr as u32, be));
                buf.extend_from_slice(&ser_u32(self.p_paddr as u32, be));
                buf.extend_from_slice(&ser_u32(self.p_filesz as u32, be));
                buf.extend_from_slice(&ser_u32(self.p_memsz as u32, be));
                buf.extend_from_slice(&ser_u32(self.p_flags, be));
                buf.extend_from_slice(&ser_u32(self.p_align as u32, be));
            },
            BitSize::Bits64 => {
                buf.extend_from_slice(&ser_u32(self.p_type, be));
                buf.extend_from_slice(&ser_u32(self.p_flags, be));
                buf.extend_from_slice(&ser_u64(self.p_offset, be));
                buf.extend_from_slice(&ser_u64(self.p_vaddr, be));
                buf.extend_from_slice(&ser_u64(self.p_paddr, be));
                buf.extend_from_slice(&ser_u64(self.p_filesz, be));
                buf.extend_from_slice(&ser_u64(self.p_memsz, be));
                buf.extend_from_slice(&ser_u64(self.p_align, be));
            },
        }
        out.write_all(&buf).map_err(ElfError::Io)
    }
}

impl Default for ElfProgramHeaderEntry {
    fn default() -> Self {
        Self::new()
    }
}

// Unused imports kept around so callers can write `use v2e_elf::program::*`.
#[allow(unused_imports)]
use crate::enums::{p_flags as pf, p_type as pt};
#[allow(unused_imports)]
use parse_u16 as _parse_u16;
#[allow(unused_imports)]
use ser_u16 as _ser_u16;
