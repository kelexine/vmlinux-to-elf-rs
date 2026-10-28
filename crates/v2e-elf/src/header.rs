// SPDX-License-Identifier: GPL-3.0-or-later

//!
//! `ElfFileHeader` — top-level ELF file header.
//!
//! The on-disk size of
//! the header depends on the word size: 52 bytes for ELF32, 64 bytes for
//! ELF64 (both include the 16-byte `e_ident`).

#![forbid(unsafe_code)]

use crate::endian::{BitSize, Endianness};
use crate::enums::{EType, EiClass, EiData, EiOsabi, EiVersion, e_ident_indexes::EI_NIDENT};
use crate::error::ElfError;
use std::io::Write;

/// Magic bytes `\x7fELF`.
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// On-disk size of the ELF32 file header (including `e_ident`).
pub const ELF32_HEADER_SIZE: usize = 52;
/// On-disk size of the ELF64 file header (including `e_ident`).
pub const ELF64_HEADER_SIZE: usize = 64;

/// `ElfFileHeader` — the top-level ELF header.
///
/// All fields are kept as plain Rust types. On serialize, the correct
/// endianness/word-size byte widths are chosen by the `serialize` method.
#[derive(Clone, Debug)]
pub struct ElfFileHeader {
    /// Endianness (drives the byte order used by `serialize`).
    pub is_big_endian: Endianness,
    /// Word size (drives the field widths used by `serialize`).
    pub is_64_bits: BitSize,

    /// `EI_MAG` — always `b"\x7fELF"`.
    pub ei_mag: [u8; 4],
    /// `EI_CLASS` — `1` (32-bit) or `2` (64-bit).
    pub ei_class: EiClass,
    /// `EI_DATA` — `1` (LE) or `2` (BE).
    pub ei_data: EiData,
    /// `EI_VERSION` — `1` (`EV_CURRENT`).
    pub ei_version: EiVersion,
    /// `EI_OSABI` — usually `ELFOSABI_SYSV`.
    pub ei_osabi: EiOsabi,
    /// `EI_ABIVERSION` — usually `0`.
    pub ei_abiversion: u8,
    /// 7 bytes of `EI_PAD`.
    pub ei_pad: [u8; 7],

    /// `e_type` — file type.
    pub e_type: EType,
    /// `e_machine` — target architecture (`EM_*`).
    pub e_machine: u16,
    /// `e_version` — usually `EV_CURRENT`.
    pub e_version: u32,
    /// `e_entry` — virtual address of the entry point.
    pub e_entry: u64,
    /// `e_phoff` — file offset of the program header table.
    pub e_phoff: u64,
    /// `e_shoff` — file offset of the section header table.
    pub e_shoff: u64,
    /// `e_flags` — architecture-specific flags.
    pub e_flags: u32,
    /// `e_ehsize` — size of this header in bytes.
    pub e_ehsize: u16,
    /// `e_phentsize` — size of one program header entry.
    pub e_phentsize: u16,
    /// `e_phnum` — number of program header entries.
    pub e_phnum: u16,
    /// `e_shentsize` — size of one section header entry.
    pub e_shentsize: u16,
    /// `e_shnum` — number of section header entries.
    pub e_shnum: u16,
    /// `e_shstrndx` — index of the section-header string table.
    pub e_shstrndx: u16,
}

impl ElfFileHeader {
    /// Construct a new header with the given endianness + word size. All
    /// other fields are zero-initialized; the caller is expected to set
    /// `e_machine`, `e_entry`, etc.
    #[must_use]
    pub fn new(is_big_endian: Endianness, is_64_bits: BitSize) -> Self {
        Self {
            is_big_endian,
            is_64_bits,
            ei_mag: ELF_MAGIC,
            ei_class: match is_64_bits {
                BitSize::Bits32 => EiClass::ELFCLASS32,
                BitSize::Bits64 => EiClass::ELFCLASS64,
            },
            ei_data: match is_big_endian {
                Endianness::Little => EiData::ELFDATA2LSB,
                Endianness::Big => EiData::ELFDATA2MSB,
            },
            ei_version: EiVersion::EV_CURRENT,
            ei_osabi: EiOsabi::ELFOSABI_SYSV,
            ei_abiversion: 0,
            ei_pad: [0; 7],
            e_type: EType::ET_NONE,
            e_machine: 0,
            e_version: EiVersion::EV_CURRENT as u32,
            e_entry: 0,
            e_phoff: 0,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: 0,
            e_phentsize: 0,
            e_phnum: 0,
            e_shentsize: 0,
            e_shnum: 0,
            e_shstrndx: 0,
        }
    }

    /// On-disk size of this header (52 for ELF32, 64 for ELF64).
    #[must_use]
    pub const fn size(&self) -> usize {
        match self.is_64_bits {
            BitSize::Bits32 => ELF32_HEADER_SIZE,
            BitSize::Bits64 => ELF64_HEADER_SIZE,
        }
    }

    /// Parse a header from `data`. Returns `ElfError::Truncated` if the
    /// input is too short, or `ElfError::InvalidIdent` if the magic or
    /// `EI_CLASS`/`EI_DATA` bytes are unrecognized.
    ///
    /// # Errors
    /// See [`ElfError`].
    pub fn parse(data: &[u8]) -> Result<Self, ElfError> {
        if data.len() < EI_NIDENT {
            return Err(ElfError::Truncated {
                offset: 0,
                needed: EI_NIDENT,
            });
        }
        if data[0..4] != ELF_MAGIC {
            return Err(ElfError::InvalidIdent {
                offset: 0,
                byte: data[0],
            });
        }
        let ei_class = EiClass::from_u8(data[4]).ok_or(ElfError::InvalidIdent {
            offset: 4,
            byte: data[4],
        })?;
        let ei_data = EiData::from_u8(data[5]).ok_or(ElfError::InvalidIdent {
            offset: 5,
            byte: data[5],
        })?;
        let is_64_bits = match ei_class {
            EiClass::ELFCLASS32 => BitSize::Bits32,
            EiClass::ELFCLASS64 => BitSize::Bits64,
        };
        let is_big_endian = match ei_data {
            EiData::ELFDATA2LSB => Endianness::Little,
            EiData::ELFDATA2MSB => Endianness::Big,
        };

        let need = match is_64_bits {
            BitSize::Bits32 => ELF32_HEADER_SIZE,
            BitSize::Bits64 => ELF64_HEADER_SIZE,
        };
        if data.len() < need {
            return Err(ElfError::Truncated {
                offset: 0,
                needed: need,
            });
        }

        let be = matches!(is_big_endian, Endianness::Big);
        let e_type = u16_from(data, 16, be);
        let e_machine = u16_from(data, 18, be);
        let e_version = u32_from(data, 20, be);
        let (e_entry, e_phoff, e_shoff) = match is_64_bits {
            BitSize::Bits32 => (
                u32_from(data, 24, be) as u64,
                u32_from(data, 28, be) as u64,
                u32_from(data, 32, be) as u64,
            ),
            BitSize::Bits64 => (
                u64_from(data, 24, be),
                u64_from(data, 32, be),
                u64_from(data, 40, be),
            ),
        };
        let e_flags = u32_from(
            data,
            match is_64_bits {
                BitSize::Bits32 => 36,
                BitSize::Bits64 => 48,
            },
            be,
        );
        let e_ehsize = u16_from(
            data,
            match is_64_bits {
                BitSize::Bits32 => 40,
                BitSize::Bits64 => 52,
            },
            be,
        );
        let e_phentsize = u16_from(
            data,
            match is_64_bits {
                BitSize::Bits32 => 42,
                BitSize::Bits64 => 54,
            },
            be,
        );
        let e_phnum = u16_from(
            data,
            match is_64_bits {
                BitSize::Bits32 => 44,
                BitSize::Bits64 => 56,
            },
            be,
        );
        let e_shentsize = u16_from(
            data,
            match is_64_bits {
                BitSize::Bits32 => 46,
                BitSize::Bits64 => 58,
            },
            be,
        );
        let e_shnum = u16_from(
            data,
            match is_64_bits {
                BitSize::Bits32 => 48,
                BitSize::Bits64 => 60,
            },
            be,
        );
        let e_shstrndx = u16_from(
            data,
            match is_64_bits {
                BitSize::Bits32 => 50,
                BitSize::Bits64 => 62,
            },
            be,
        );

        Ok(Self {
            is_big_endian,
            is_64_bits,
            ei_mag: ELF_MAGIC,
            ei_class,
            ei_data,
            ei_version: EiVersion::EV_CURRENT,
            ei_osabi: EiOsabi::ELFOSABI_SYSV,
            ei_abiversion: 0,
            ei_pad: [0; 7],
            e_type: match e_type {
                0 => EType::ET_NONE,
                1 => EType::ET_REL,
                2 => EType::ET_EXEC,
                3 => EType::ET_DYN,
                4 => EType::ET_CORE,
                _ => EType::ET_NONE,
            },
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        })
    }

    /// Serialize the header to `out`. Writes exactly `self.size()` bytes.
    ///
    /// # Errors
    /// Returns [`ElfError::Io`] only if the underlying writer fails.
    pub fn serialize<W: Write>(&self, out: &mut W) -> Result<(), ElfError> {
        let mut buf = Vec::with_capacity(self.size());
        buf.extend_from_slice(&self.ei_mag);
        buf.push(self.ei_class.to_u8());
        buf.push(self.ei_data.to_u8());
        buf.push(self.ei_version as u8);
        buf.push(self.ei_osabi as u8);
        buf.push(self.ei_abiversion);
        buf.extend_from_slice(&self.ei_pad);

        let be = matches!(self.is_big_endian, Endianness::Big);
        buf.extend_from_slice(&u16_bytes(self.e_type.to_u16(), be));
        buf.extend_from_slice(&u16_bytes(self.e_machine, be));
        buf.extend_from_slice(&u32_bytes(self.e_version, be));

        match self.is_64_bits {
            BitSize::Bits32 => {
                buf.extend_from_slice(&u32_bytes(self.e_entry as u32, be));
                buf.extend_from_slice(&u32_bytes(self.e_phoff as u32, be));
                buf.extend_from_slice(&u32_bytes(self.e_shoff as u32, be));
            },
            BitSize::Bits64 => {
                buf.extend_from_slice(&u64_bytes(self.e_entry, be));
                buf.extend_from_slice(&u64_bytes(self.e_phoff, be));
                buf.extend_from_slice(&u64_bytes(self.e_shoff, be));
            },
        }
        buf.extend_from_slice(&u32_bytes(self.e_flags, be));
        buf.extend_from_slice(&u16_bytes(self.e_ehsize, be));
        buf.extend_from_slice(&u16_bytes(self.e_phentsize, be));
        buf.extend_from_slice(&u16_bytes(self.e_phnum, be));
        buf.extend_from_slice(&u16_bytes(self.e_shentsize, be));
        buf.extend_from_slice(&u16_bytes(self.e_shnum, be));
        buf.extend_from_slice(&u16_bytes(self.e_shstrndx, be));

        debug_assert_eq!(buf.len(), self.size());
        out.write_all(&buf).map_err(ElfError::Io)
    }
}

#[inline]
pub fn u16_from(data: &[u8], off: usize, be: bool) -> u16 {
    if be {
        u16::from_be_bytes([data[off], data[off + 1]])
    } else {
        u16::from_le_bytes([data[off], data[off + 1]])
    }
}
#[inline]
pub fn u32_from(data: &[u8], off: usize, be: bool) -> u32 {
    if be {
        u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
    } else {
        u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
    }
}
#[inline]
pub fn u64_from(data: &[u8], off: usize, be: bool) -> u64 {
    if be {
        u64::from_be_bytes([
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
            data[off + 4],
            data[off + 5],
            data[off + 6],
            data[off + 7],
        ])
    } else {
        u64::from_le_bytes([
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
            data[off + 4],
            data[off + 5],
            data[off + 6],
            data[off + 7],
        ])
    }
}
#[inline]
pub fn u16_bytes(v: u16, be: bool) -> [u8; 2] {
    if be { v.to_be_bytes() } else { v.to_le_bytes() }
}
#[inline]
pub fn u32_bytes(v: u32, be: bool) -> [u8; 4] {
    if be { v.to_be_bytes() } else { v.to_le_bytes() }
}
#[inline]
pub fn u64_bytes(v: u64, be: bool) -> [u8; 8] {
    if be { v.to_be_bytes() } else { v.to_le_bytes() }
}

pub use {u16_bytes as ser_u16, u32_bytes as ser_u32, u64_bytes as ser_u64};
pub use {u16_from as parse_u16, u32_from as parse_u32, u64_from as parse_u64};
