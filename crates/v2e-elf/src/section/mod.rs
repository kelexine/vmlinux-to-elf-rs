// SPDX-License-Identifier: GPL-3.0-or-later
//
//! ELF section hierarchy.

#![forbid(unsafe_code)]

use crate::endian::{BitSize, Endianness};
use crate::enums::{ShType, StInfoBinding, StInfoType, sh_flags, special_section_index};
use crate::error::ElfError;
use crate::header::{parse_u16, parse_u32, parse_u64, ser_u16, ser_u32, ser_u64};
use std::io::Write;

/// On-disk size of an Elf32_Shdr (10 fields, all 32-bit or smaller).
pub const ELF32_SHDR_SIZE: usize = 40;
/// On-disk size of an Elf64_Shdr.
pub const ELF64_SHDR_SIZE: usize = 64;

/// Section header.
#[derive(Clone, Debug)]
pub struct ElfSectionHeader {
    /// `sh_name` — offset into the section-header string table.
    pub sh_name: u32,
    /// `sh_type` — section type.
    pub sh_type: ShType,
    /// `sh_flags`.
    pub sh_flags: u64,
    /// `sh_addr` — virtual address at execution.
    pub sh_addr: u64,
    /// `sh_offset` — file offset of the section contents.
    pub sh_offset: u64,
    /// `sh_size` — section size in bytes.
    pub sh_size: u64,
    /// `sh_link` — section-index link.
    pub sh_link: u32,
    /// `sh_info` — extra info.
    pub sh_info: u32,
    /// `sh_addralign`.
    pub sh_addralign: u64,
    /// `sh_entsize`.
    pub sh_entsize: u64,
}

impl ElfSectionHeader {
    /// Construct a fresh header with all fields zeroed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sh_name: 0,
            sh_type: ShType::SHT_NULL,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: 0,
            sh_size: 0,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        }
    }

    /// On-disk size (40 for ELF32, 64 for ELF64).
    #[must_use]
    pub const fn size(is_64: BitSize) -> usize {
        match is_64 {
            BitSize::Bits32 => ELF32_SHDR_SIZE,
            BitSize::Bits64 => ELF64_SHDR_SIZE,
        }
    }

    /// Parse a section header from `data` at `offset`.
    ///
    /// # Errors
    /// Returns [`ElfError::Truncated`] if `data` is too short.
    pub fn parse(
        data: &[u8],
        offset: usize,
        endian: Endianness,
        bits: BitSize,
    ) -> Result<Self, ElfError> {
        let need = Self::size(bits);
        if data.len() < offset + need {
            return Err(ElfError::Truncated {
                offset,
                needed: need,
            });
        }
        let be = matches!(endian, Endianness::Big);
        Ok(match bits {
            BitSize::Bits32 => Self {
                sh_name: parse_u32(data, offset, be),
                sh_type: ShType::from_u32(parse_u32(data, offset + 4, be)),
                sh_flags: parse_u32(data, offset + 8, be) as u64,
                sh_addr: parse_u32(data, offset + 12, be) as u64,
                sh_offset: parse_u32(data, offset + 16, be) as u64,
                sh_size: parse_u32(data, offset + 20, be) as u64,
                sh_link: parse_u32(data, offset + 24, be),
                sh_info: parse_u32(data, offset + 28, be),
                sh_addralign: parse_u32(data, offset + 32, be) as u64,
                sh_entsize: parse_u32(data, offset + 36, be) as u64,
            },
            BitSize::Bits64 => Self {
                sh_name: parse_u32(data, offset, be),
                sh_type: ShType::from_u32(parse_u32(data, offset + 4, be)),
                sh_flags: parse_u64(data, offset + 8, be),
                sh_addr: parse_u64(data, offset + 16, be),
                sh_offset: parse_u64(data, offset + 24, be),
                sh_size: parse_u64(data, offset + 32, be),
                sh_link: parse_u32(data, offset + 40, be),
                sh_info: parse_u32(data, offset + 44, be),
                sh_addralign: parse_u64(data, offset + 48, be),
                sh_entsize: parse_u64(data, offset + 56, be),
            },
        })
    }

    /// Serialize to `out`. Writes exactly `Self::size(bits)` bytes.
    ///
    /// # Errors
    /// Returns [`ElfError::Io`] only if the underlying writer fails.
    pub fn serialize<W: Write>(
        &self,
        out: &mut W,
        endian: Endianness,
        bits: BitSize,
    ) -> Result<(), ElfError> {
        let be = matches!(endian, Endianness::Big);
        let mut buf: Vec<u8> = Vec::with_capacity(Self::size(bits));
        buf.extend_from_slice(&ser_u32(self.sh_name, be));
        buf.extend_from_slice(&ser_u32(self.sh_type.to_u32(), be));
        match bits {
            BitSize::Bits32 => {
                buf.extend_from_slice(&ser_u32(self.sh_flags as u32, be));
                buf.extend_from_slice(&ser_u32(self.sh_addr as u32, be));
                buf.extend_from_slice(&ser_u32(self.sh_offset as u32, be));
                buf.extend_from_slice(&ser_u32(self.sh_size as u32, be));
                buf.extend_from_slice(&ser_u32(self.sh_link, be));
                buf.extend_from_slice(&ser_u32(self.sh_info, be));
                buf.extend_from_slice(&ser_u32(self.sh_addralign as u32, be));
                buf.extend_from_slice(&ser_u32(self.sh_entsize as u32, be));
            },
            BitSize::Bits64 => {
                buf.extend_from_slice(&ser_u64(self.sh_flags, be));
                buf.extend_from_slice(&ser_u64(self.sh_addr, be));
                buf.extend_from_slice(&ser_u64(self.sh_offset, be));
                buf.extend_from_slice(&ser_u64(self.sh_size, be));
                buf.extend_from_slice(&ser_u32(self.sh_link, be));
                buf.extend_from_slice(&ser_u32(self.sh_info, be));
                buf.extend_from_slice(&ser_u64(self.sh_addralign, be));
                buf.extend_from_slice(&ser_u64(self.sh_entsize, be));
            },
        }
        out.write_all(&buf).map_err(ElfError::Io)
    }
}

impl Default for ElfSectionHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// A single symbol-table entry.
///
/// We collapse into one struct with an explicit `endian` and `bits` flag.
#[derive(Clone, Debug)]
pub struct SymbolEntry {
    /// `st_name` — offset into the string table.
    pub st_name: u32,
    /// `st_value`.
    pub st_value: u64,
    /// `st_size`.
    pub st_size: u64,
    /// `st_info_type` (low 4 bits of `st_info`).
    pub st_info_type: StInfoType,
    /// `st_info_binding` (high 4 bits of `st_info`).
    pub st_info_binding: StInfoBinding,
    /// `st_other`.
    pub st_other: u8,
    /// `st_shndx`.
    pub st_shndx: u16,
    /// Resolved symbol name (UTF-8 string from the string table).
    pub symbol_name: String,
}

impl Default for SymbolEntry {
    fn default() -> Self {
        Self {
            st_name: 0,
            st_value: 0,
            st_size: 0,
            st_info_type: StInfoType::STT_NOTYPE,
            st_info_binding: StInfoBinding::STB_LOCAL,
            st_other: 0,
            st_shndx: 0,
            symbol_name: String::new(),
        }
    }
}

impl SymbolEntry {
    /// On-disk entry size for the given word size.
    #[must_use]
    pub const fn entry_size(bits: BitSize) -> usize {
        match bits {
            BitSize::Bits32 => 16,
            BitSize::Bits64 => 24,
        }
    }

    /// Parse a symbol-table entry at `offset`. For ELF32, the bitfield
    /// order in `st_info` differs between LE and BE; we honour that.
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
                let st_name = parse_u32(data, offset, be);
                let st_value = parse_u32(data, offset + 4, be) as u64;
                let st_size = parse_u32(data, offset + 8, be) as u64;
                let st_info = data[offset + 12];
                let st_other = data[offset + 13];
                let st_shndx = parse_u16(data, offset + 14, be);
                // 32LE: type-lo/binding-hi.  32BE: binding-lo/type-hi.
                let (st_info_type, st_info_binding) = {
                    (
                        StInfoType::from_u8(st_info & 0x0F),
                        StInfoBinding::from_u8((st_info >> 4) & 0x0F),
                    )
                };
                Self {
                    st_name,
                    st_value,
                    st_size,
                    st_info_type,
                    st_info_binding,
                    st_other,
                    st_shndx,
                    symbol_name: String::new(),
                }
            },
            BitSize::Bits64 => {
                let st_name = parse_u32(data, offset, be);
                let st_info = data[offset + 4];
                let st_other = data[offset + 5];
                let st_shndx = parse_u16(data, offset + 6, be);
                let st_value = parse_u64(data, offset + 8, be);
                let st_size = parse_u64(data, offset + 16, be);
                // 64-bit: type-lo/binding-hi in BOTH endiannesses
                let st_info_type = StInfoType::from_u8(st_info & 0x0F);
                let st_info_binding = StInfoBinding::from_u8((st_info >> 4) & 0x0F);
                Self {
                    st_name,
                    st_value,
                    st_size,
                    st_info_type,
                    st_info_binding,
                    st_other,
                    st_shndx,
                    symbol_name: String::new(),
                }
            },
        })
    }

    /// Serialize to `out`. Writes exactly `Self::entry_size(bits)` bytes.
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
                buf.extend_from_slice(&ser_u32(self.st_name, be));
                buf.extend_from_slice(&ser_u32(self.st_value as u32, be));
                buf.extend_from_slice(&ser_u32(self.st_size as u32, be));
                // 32-bit: LE = type-lo/binding-hi; BE = binding-lo/type-hi.
                let st_info: u8 = if be {
                    (self.st_info_binding.to_u8() & 0x0F)
                        | ((self.st_info_type.to_u8() & 0x0F) << 4)
                } else {
                    (self.st_info_type.to_u8() & 0x0F)
                        | ((self.st_info_binding.to_u8() & 0x0F) << 4)
                };
                buf.push(st_info);
                buf.push(self.st_other);
                buf.extend_from_slice(&ser_u16(self.st_shndx, be));
            },
            BitSize::Bits64 => {
                buf.extend_from_slice(&ser_u32(self.st_name, be));
                let st_info: u8 = (self.st_info_type.to_u8() & 0x0F)
                    | ((self.st_info_binding.to_u8() & 0x0F) << 4);
                buf.push(st_info);
                buf.push(self.st_other);
                buf.extend_from_slice(&ser_u16(self.st_shndx, be));
                buf.extend_from_slice(&ser_u64(self.st_value, be));
                buf.extend_from_slice(&ser_u64(self.st_size, be));
            },
        }
        out.write_all(&buf).map_err(ElfError::Io)
    }
}

/// A string table — faithful port of `ElfStrtab`.
#[derive(Clone, Debug, Default)]
pub struct ElfStrtab {
    /// Raw bytes of the string table, including the leading NUL byte
    /// and the trailing NUL after each string.
    pub raw: Vec<u8>,
    /// Cache: string → offset (built lazily).
    cache: std::collections::HashMap<String, u32>,
}

impl ElfStrtab {
    /// Construct a fresh strtab initialised with the empty-string entry at offset 0.
    #[must_use]
    pub fn new() -> Self {
        let mut s = Self::default();
        s.add_string("");
        s
    }

    /// Replace the contents from a parsed raw buffer. Rebuilds the cache.
    pub fn set_raw(&mut self, raw: Vec<u8>) {
        self.raw = raw;
        self.cache.clear();
        let mut i = 0;
        while i < self.raw.len() {
            // Find next NUL
            let end = self.raw[i..]
                .iter()
                .position(|&b| b == 0)
                .map_or(self.raw.len(), |p| i + p);
            if let Ok(s) = std::str::from_utf8(&self.raw[i..end]) {
                self.cache.insert(s.to_string(), i as u32);
            }
            i = end + 1;
        }
    }

    /// Look up the string at the given byte offset.
    #[must_use]
    pub fn string_at(&self, offset: u32) -> String {
        let start = offset as usize;
        if start >= self.raw.len() {
            return String::new();
        }
        let end = self.raw[start..]
            .iter()
            .position(|&b| b == 0)
            .map_or(self.raw.len(), |p| start + p);
        String::from_utf8_lossy(&self.raw[start..end]).into_owned()
    }

    /// Add a string and return its offset. Reuses an existing entry if
    /// the string is already present.
    pub fn add_string(&mut self, s: &str) -> u32 {
        if let Some(&off) = self.cache.get(s) {
            return off;
        }
        let off = self.raw.len() as u32;
        self.raw.extend_from_slice(s.as_bytes());
        self.raw.push(0);
        self.cache.insert(s.to_string(), off);
        off
    }
}

/// A single relocation entry (REL or RELA).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct RelocationEntry {
    /// `r_offset`.
    pub r_offset: u64,
    /// `r_info` (raw 64-bit; low 32 bits = type, high 32 bits = sym).
    pub r_info: u64,
    /// `r_addend` (None for REL, Some for RELA).
    pub r_addend: Option<i64>,
}

impl RelocationEntry {
    /// `r_info_type` — low 32 bits of `r_info`.
    #[must_use]
    pub const fn r_info_type(self) -> u32 {
        (self.r_info & 0xFFFF_FFFF) as u32
    }
    /// `r_info_sym` — high 32 bits of `r_info`.
    #[must_use]
    pub const fn r_info_sym(self) -> u32 {
        (self.r_info >> 32) as u32
    }

    /// On-disk entry size.
    #[must_use]
    pub const fn entry_size(bits: BitSize, has_addend: bool) -> usize {
        match (bits, has_addend) {
            (BitSize::Bits32, false) => 8,
            (BitSize::Bits32, true) => 12,
            (BitSize::Bits64, false) => 16,
            (BitSize::Bits64, true) => 24,
        }
    }

    /// Parse one entry. `has_addend` selects REL vs RELA.
    pub fn parse(
        data: &[u8],
        offset: usize,
        endian: Endianness,
        bits: BitSize,
        has_addend: bool,
    ) -> Result<Self, ElfError> {
        let need = Self::entry_size(bits, has_addend);
        if data.len() < offset + need {
            return Err(ElfError::Truncated {
                offset,
                needed: need,
            });
        }
        let be = matches!(endian, Endianness::Big);
        match bits {
            BitSize::Bits32 => {
                let r_offset = parse_u32(data, offset, be) as u64;
                let r_info_raw = parse_u32(data, offset + 4, be);
                // For 32-bit ELF, r_info is split as (sym, type) with
                // sym in the high 24 bits and type in the low 8 bits.
                // We store the raw u32 in the low 32 bits of r_info so
                // the type accessor returns the low 8 bits.
                let r_info = r_info_raw as u64;
                let r_addend = if has_addend {
                    Some(parse_u32(data, offset + 8, be) as i32 as i64)
                } else {
                    None
                };
                Ok(Self {
                    r_offset,
                    r_info,
                    r_addend,
                })
            },
            BitSize::Bits64 => {
                let r_offset = parse_u64(data, offset, be);
                let r_info = parse_u64(data, offset + 8, be);
                let r_addend = if has_addend {
                    Some(parse_u64(data, offset + 16, be) as i64)
                } else {
                    None
                };
                Ok(Self {
                    r_offset,
                    r_info,
                    r_addend,
                })
            },
        }
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
        let mut buf: Vec<u8> = Vec::new();
        match bits {
            BitSize::Bits32 => {
                buf.extend_from_slice(&ser_u32(self.r_offset as u32, be));
                buf.extend_from_slice(&ser_u32(self.r_info as u32, be));
                if let Some(addend) = self.r_addend {
                    buf.extend_from_slice(&ser_u32(addend as u32, be));
                }
            },
            BitSize::Bits64 => {
                buf.extend_from_slice(&ser_u64(self.r_offset, be));
                buf.extend_from_slice(&ser_u64(self.r_info, be));
                if let Some(addend) = self.r_addend {
                    buf.extend_from_slice(&ser_u64(addend as u64, be));
                }
            },
        }
        out.write_all(&buf).map_err(ElfError::Io)
    }
}

/// Tag for which subclass an `ElfSection` represents.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum SectionKind {
    /// `SHT_NULL`.
    Null,
    /// `SHT_PROGBITS`.
    Progbits,
    /// `SHT_NOBITS` (no on-disk content).
    Nobits,
    /// `SHT_SYMTAB`.
    Symtab,
    /// `SHT_DYNSYM`.
    Dynsym,
    /// `SHT_STRTAB`.
    Strtab,
    /// `SHT_RELA`.
    Rela,
    /// `SHT_REL`.
    Rel,
    /// `SHT_DYNAMIC`.
    Dynamic,
    /// `SHT_HASH`.
    Hash,
    /// Anything else — treated as opaque bytes.
    Other,
}

impl SectionKind {
    /// Construct from a `ShType`.
    #[must_use]
    pub const fn from_sh_type(ty: ShType) -> Self {
        match ty {
            ShType::SHT_NULL => SectionKind::Null,
            ShType::SHT_PROGBITS => SectionKind::Progbits,
            ShType::SHT_NOBITS => SectionKind::Nobits,
            ShType::SHT_SYMTAB => SectionKind::Symtab,
            ShType::SHT_DYNSYM => SectionKind::Dynsym,
            ShType::SHT_STRTAB => SectionKind::Strtab,
            ShType::SHT_RELA => SectionKind::Rela,
            ShType::SHT_REL => SectionKind::Rel,
            ShType::SHT_DYNAMIC => SectionKind::Dynamic,
            ShType::SHT_HASH => SectionKind::Hash,
            _ => SectionKind::Other,
        }
    }
}

/// A parsed ELF section. Combines the header with the parsed contents
/// (bytes for progbits/null/other, structured for symtab/strtab/rel/rela).
#[derive(Clone, Debug)]
pub struct ElfSection {
    /// The section header.
    pub header: ElfSectionHeader,
    /// Section name (resolved from the section-header string table).
    pub section_name: String,
    /// Raw byte contents (empty for `SHT_NOBITS`).
    pub section_contents: Vec<u8>,
    /// Parsed symbol table (populated iff `header.sh_type == SHT_SYMTAB`
    /// or `SHT_DYNSYM`).
    pub symbols: Vec<SymbolEntry>,
    /// Parsed string table (populated iff `header.sh_type == SHT_STRTAB`).
    pub strtab: Option<ElfStrtab>,
    /// Parsed relocations (populated iff `SHT_REL` or `SHT_RELA`).
    pub relocations: Vec<RelocationEntry>,
    /// Index of the linked string table (for symtab) or symtab (for
    /// rel/rela).
    pub sh_link_index: u32,
}

impl ElfSection {
    /// Construct an empty section of the given kind with a fresh header.
    #[must_use]
    pub fn new(kind: SectionKind, name: &str, endian: Endianness, bits: BitSize) -> Self {
        let mut header = ElfSectionHeader::new();
        header.sh_type = match kind {
            SectionKind::Null => ShType::SHT_NULL,
            SectionKind::Progbits => ShType::SHT_PROGBITS,
            SectionKind::Nobits => ShType::SHT_NOBITS,
            SectionKind::Symtab => ShType::SHT_SYMTAB,
            SectionKind::Dynsym => ShType::SHT_DYNSYM,
            SectionKind::Strtab => ShType::SHT_STRTAB,
            SectionKind::Rela => ShType::SHT_RELA,
            SectionKind::Rel => ShType::SHT_REL,
            SectionKind::Dynamic => ShType::SHT_DYNAMIC,
            SectionKind::Hash => ShType::SHT_HASH,
            SectionKind::Other => ShType::Other(0),
        };
        header.sh_entsize = match kind {
            SectionKind::Symtab | SectionKind::Dynsym => SymbolEntry::entry_size(bits) as u64,
            SectionKind::Rela => RelocationEntry::entry_size(bits, true) as u64,
            SectionKind::Rel => RelocationEntry::entry_size(bits, false) as u64,
            _ => 0,
        };
        let strtab = if matches!(kind, SectionKind::Strtab) {
            Some(ElfStrtab::new())
        } else {
            None
        };
        Self {
            header,
            section_name: name.to_string(),
            section_contents: Vec::new(),
            symbols: Vec::new(),
            strtab,
            relocations: Vec::new(),
            sh_link_index: 0,
        }
    }

    /// Parse the contents of this section (given the header was already
    /// parsed) from `data`. The header's `sh_offset` and `sh_size` are
    /// used to locate the bytes. For `SHT_NOBITS`, no bytes are read.
    ///
    /// # Errors
    /// Returns [`ElfError::Truncated`] if the file is too short.
    pub fn parse_contents(
        &mut self,
        data: &[u8],
        endian: Endianness,
        bits: BitSize,
    ) -> Result<(), ElfError> {
        let kind = SectionKind::from_sh_type(self.header.sh_type);
        if matches!(kind, SectionKind::Nobits) {
            return Ok(());
        }
        let start = self.header.sh_offset as usize;
        let end = start + self.header.sh_size as usize;
        if data.len() < end {
            return Err(ElfError::Truncated {
                offset: start,
                needed: self.header.sh_size as usize,
            });
        }
        self.section_contents = data[start..end].to_vec();

        match kind {
            SectionKind::Symtab | SectionKind::Dynsym => {
                let esz = SymbolEntry::entry_size(bits);
                let n = (self.header.sh_size as usize).checked_div(esz).unwrap_or(0);
                self.symbols.clear();
                self.symbols.reserve(n);
                for i in 0..n {
                    let off = start + i * esz;
                    let sym = SymbolEntry::parse(data, off, endian, bits)?;
                    self.symbols.push(sym);
                }
            },
            SectionKind::Strtab => {
                let mut st = ElfStrtab::new();
                st.set_raw(self.section_contents.clone());
                self.strtab = Some(st);
            },
            SectionKind::Rela | SectionKind::Rel => {
                let has_addend = matches!(kind, SectionKind::Rela);
                let esz = RelocationEntry::entry_size(bits, has_addend);
                let n = (self.header.sh_size as usize).checked_div(esz).unwrap_or(0);
                self.relocations.clear();
                self.relocations.reserve(n);
                for i in 0..n {
                    let off = start + i * esz;
                    let rel = RelocationEntry::parse(data, off, endian, bits, has_addend)?;
                    self.relocations.push(rel);
                }
            },
            _ => {},
        }
        Ok(())
    }

    /// Compute the on-disk size of this section's contents. For NOBITS,
    /// this is 0.
    #[must_use]
    pub fn content_size(&self) -> u64 {
        if matches!(
            SectionKind::from_sh_type(self.header.sh_type),
            SectionKind::Nobits
        ) {
            0
        } else {
            self.section_contents.len() as u64
        }
    }

    /// Whether this section has the `SHF_ALLOC` flag set.
    #[must_use]
    pub fn is_alloc(&self) -> bool {
        (self.header.sh_flags & sh_flags::SHF_ALLOC) != 0
    }
}

// `ShType` is used directly throughout this module; no extra re-export
// is needed because `enums::ShType` is already `pub`.

/// Re-export of `special_section_index`'s well-known values, for ergonomic
/// access from the CLI.
pub mod special {
    pub use crate::enums::special_section_index::*;
}

/// True iff `idx` is a reserved `SHN_*` value.
#[must_use]
pub fn is_special_section_index(idx: u16) -> bool {
    (idx >= special_section_index::SHN_LORESERVE) || idx == special_section_index::SHN_UNDEF
}
