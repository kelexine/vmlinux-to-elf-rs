// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `ElfFile` — top-level ELF orchestrator.

#![forbid(unsafe_code)]

use crate::endian::{BitSize, Endianness};
use crate::enums::ShType;
use crate::enums::{
    e_ident_indexes::{EI_CLASS, EI_DATA, EI_NIDENT},
    p_flags, p_type,
    sh_flags::{self, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE},
    special_section_index, EiClass, EiData,
};
use crate::error::ElfError;
use crate::header::{ElfFileHeader, ELF_MAGIC};
use crate::program::ElfProgramHeaderEntry;
use crate::section::{ElfSection, ElfSectionHeader, ElfStrtab, SectionKind};
use std::io::Write;

/// Top-level ELF object — owns the header, sections, and (optionally) the program-header table.
#[derive(Clone, Debug)]
pub struct ElfFile {
    /// Endianness.
    pub is_big_endian: Endianness,
    /// Word size.
    pub is_64_bits: BitSize,
    /// File header.
    pub file_header: ElfFileHeader,
    /// All sections, in declaration order.
    pub sections: Vec<ElfSection>,
    /// Program-header entries (recomputed on serialize).
    pub segments: Vec<ElfProgramHeaderEntry>,
    /// Index of the section-header string table (`e_shstrndx`).
    pub section_string_table_index: Option<usize>,
    /// Index of the symbol table (the `SHT_SYMTAB` section).
    pub symbol_table_index: Option<usize>,
}

/// Immutable address → section-index map built by [`ElfFile::section_locator`].
///
/// Selection rule (identical to the reference implementation): among sections
/// with a non-zero `sh_addr`, pick the *last* one whose start is `<= address`,
/// then accept it only if `address <= sh_addr + sh_size` (inclusive end).
#[derive(Clone, Debug, Default)]
pub struct SectionLocator {
    /// `(sh_addr, sh_size, section index)`, sorted by `sh_addr` (stable).
    entries: Vec<(u64, u64, usize)>,
}

impl SectionLocator {
    /// Index of the section containing `address`, if any.
    #[must_use]
    pub fn find(&self, address: u64) -> Option<usize> {
        let upto = self
            .entries
            .partition_point(|&(start, _, _)| start <= address);
        let &(start, size, idx) = self.entries.get(upto.checked_sub(1)?)?;
        (address <= start.saturating_add(size)).then_some(idx)
    }
}

impl ElfFile {
    /// Construct an empty ELF object with the given endianness + word size.
    #[must_use]
    pub fn new(is_big_endian: Endianness, is_64_bits: BitSize) -> Self {
        Self {
            is_big_endian,
            is_64_bits,
            file_header: ElfFileHeader::new(is_big_endian, is_64_bits),
            sections: Vec::new(),
            segments: Vec::new(),
            section_string_table_index: None,
            symbol_table_index: None,
        }
    }

    /// Parse an ELF file from a byte slice.
    ///
    /// # Errors
    /// Returns [`ElfError`] on any parse failure.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ElfError> {
        let header = ElfFileHeader::parse(data)?;
        let endian = header.is_big_endian;
        let bits = header.is_64_bits;

        // Parse section headers
        let mut sections: Vec<ElfSection> = Vec::with_capacity(header.e_shnum as usize);
        for i in 0..header.e_shnum {
            let off = header.e_shoff as usize + header.e_shentsize as usize * i as usize;
            let shdr = ElfSectionHeader::parse(data, off, endian, bits)?;
            let mut section = ElfSection {
                header: shdr,
                section_name: String::new(),
                section_contents: Vec::new(),
                symbols: Vec::new(),
                strtab: None,
                relocations: Vec::new(),
                sh_link_index: 0,
            };
            section.parse_contents(data, endian, bits)?;
            sections.push(section);
        }

        // Parse program-header entries.
        let phnum = if header.e_phnum == crate::enums::special_segment_index::PN_XNUM {
            // PN_XNUM trick — first section's sh_info holds the real count.
            sections.first().map(|s| s.header.sh_info).unwrap_or(0)
        } else {
            header.e_phnum as u32
        };
        let mut segments: Vec<ElfProgramHeaderEntry> = Vec::with_capacity(phnum as usize);
        for i in 0..phnum {
            let off = header.e_phoff as usize + header.e_phentsize as usize * i as usize;
            segments.push(ElfProgramHeaderEntry::parse(data, off, endian, bits)?);
        }

        // Resolve section names from the section-header string table.
        let shstrndx = header.e_shstrndx as usize;
        let mut section_string_table_index = None;
        if shstrndx != special_section_index::SHN_XINDEX as usize && shstrndx < sections.len() {
            section_string_table_index = Some(shstrndx);
            // Make sure the strtab section is parsed as a strtab.
            let kind = SectionKind::from_sh_type(sections[shstrndx].header.sh_type);
            if !matches!(kind, SectionKind::Strtab) {
                // Force it.
                sections[shstrndx].strtab = Some(ElfStrtab::new());
                if !sections[shstrndx].section_contents.is_empty() {
                    let raw = sections[shstrndx].section_contents.clone();
                    sections[shstrndx].strtab = {
                        let mut st = ElfStrtab::new();
                        st.set_raw(raw);
                        Some(st)
                    };
                }
            } else if sections[shstrndx].strtab.is_none() {
                let raw = sections[shstrndx].section_contents.clone();
                let mut st = ElfStrtab::new();
                st.set_raw(raw);
                sections[shstrndx].strtab = Some(st);
            }
        }

        // Now resolve names + symtab link.
        let strtab_snapshot: Option<ElfStrtab> =
            section_string_table_index.and_then(|i| sections[i].strtab.clone());
        let mut symbol_table_index = None;
        for (i, s) in sections.iter_mut().enumerate() {
            if let Some(st) = &strtab_snapshot {
                s.section_name = st.string_at(s.header.sh_name);
            }
            if matches!(
                SectionKind::from_sh_type(s.header.sh_type),
                SectionKind::Symtab
            ) {
                symbol_table_index = Some(i);
            }
        }

        // Resolve symbol names + sh_link_index back-pointers for symtab/rela.
        if let Some(sidx) = symbol_table_index {
            // sh_link points to the strtab used by the symtab.
            let link = sections[sidx].header.sh_link as usize;
            if link < sections.len() {
                let raw = sections[link].section_contents.clone();
                let mut st = ElfStrtab::new();
                st.set_raw(raw);
                for sym in &mut sections[sidx].symbols {
                    sym.symbol_name = st.string_at(sym.st_name);
                }
            }
        }
        // Resolve relocation-table sh_link (points to the symtab).
        for i in 0..sections.len() {
            let kind = SectionKind::from_sh_type(sections[i].header.sh_type);
            if matches!(kind, SectionKind::Rel | SectionKind::Rela) {
                let link = sections[i].header.sh_link;
                sections[i].sh_link_index = link;
            }
        }

        Ok(Self {
            is_big_endian: endian,
            is_64_bits: bits,
            file_header: header,
            sections,
            segments,
            section_string_table_index,
            symbol_table_index,
        })
    }

    /// Binary-search the section that contains `address`.
    #[must_use]
    pub fn find_section(&self, address: u64) -> Option<&ElfSection> {
        self.find_section_index(address).map(|i| &self.sections[i])
    }

    /// Index (into [`ElfFile::sections`]) of the section that contains `address`.
    ///
    /// Mirrors the reference implementation exactly: only sections with a
    /// non-zero `sh_addr` participate, they are ordered by `sh_addr` (stable,
    /// so ties keep declaration order), and the *last* section whose start is
    /// `<= address` is selected. The end bound is inclusive. Consequently an
    /// address that sits exactly on a section boundary resolves to the section
    /// that *starts* there, not the one that ends there.
    #[must_use]
    pub fn find_section_index(&self, address: u64) -> Option<usize> {
        self.section_locator().find(address)
    }

    /// Snapshot of the section address map for repeated lookups (e.g. one per
    /// kallsyms symbol). Build once, call [`SectionLocator::find`] many times.
    #[must_use]
    pub fn section_locator(&self) -> SectionLocator {
        let mut entries: Vec<(u64, u64, usize)> = self
            .sections
            .iter()
            .enumerate()
            .filter(|(_, s)| s.header.sh_addr > 0)
            .map(|(i, s)| (s.header.sh_addr, s.header.sh_size, i))
            .collect();
        // Stable: sections sharing an address keep declaration order.
        entries.sort_by_key(|&(start, _, _)| start);
        SectionLocator { entries }
    }

    /// Serialize the ELF file to `out`. Layout produced:
    ///
    /// ```text
    /// [ File header | Section headers | Section contents | Program headers ]
    /// ```
    ///
    /// # Errors
    /// Returns [`ElfError`] on any failure (including I/O).
    pub fn serialize<W: Write>(&self, out: &mut W) -> Result<(), ElfError> {
        // Filter out .gnu.version sections.
        let filtered_idxs: Vec<usize> = self
            .sections
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.section_name.contains(".gnu.version"))
            .map(|(i, _)| i)
            .collect();

        // Compute e_ehsize.
        let ehsize = self.file_header.size() as u16;
        let mut header = self.file_header.clone();
        header.e_ehsize = ehsize;

        // Compute e_shstrndx.
        let shstrndx = self.section_string_table_index;
        if let Some(idx) = shstrndx {
            let real_idx = filtered_idxs
                .iter()
                .position(|&i| i == idx)
                .map(|p| p as u16);
            if let Some(real) = real_idx {
                if (real as u32) < special_section_index::SHN_LORESERVE as u32 {
                    header.e_shstrndx = real;
                } else {
                    header.e_shstrndx = special_section_index::SHN_XINDEX;
                }
            }
        }

        // Section-header table comes right after the file header.
        header.e_shoff = ehsize as u64;
        header.e_shnum = filtered_idxs.len() as u16;
        header.e_shentsize = ElfSectionHeader::size(self.is_64_bits) as u16;

        // Pre-serialize: recompute sh_name for every section.
        // We need a mutable view of the strtab. Construct a temporary list
        // of (filtered_idx, mut section) where we patch headers as needed.
        let mut sections: Vec<ElfSection> = filtered_idxs
            .iter()
            .map(|&i| self.sections[i].clone())
            .collect();

        // Locate the section-header string table in the filtered list.
        let shstr_filter_pos =
            shstrndx.and_then(|idx| filtered_idxs.iter().position(|&i| i == idx));

        // Recompute sh_name for each section.
        if let Some(spos) = shstr_filter_pos {
            // Build the new string table from the section names of the
            // filtered sections.
            let mut st = ElfStrtab::new();
            for s in &mut sections {
                let off = st.add_string(&s.section_name);
                s.header.sh_name = off;
            }
            sections[spos].strtab = Some(st.clone());
            sections[spos].section_contents = st.raw.clone();
        }

        // Compute file offsets for section contents.
        let sh_end =
            header.e_shoff as usize + header.e_shentsize as usize * header.e_shnum as usize;

        // First, walk sections in order to assign sh_offset / sh_size, honoring
        // sh_addralign. Skip NOBITS for size accounting (sh_offset still set).
        let mut cursor = sh_end;
        for s in &mut sections {
            // Alignment (the reference rounds the offset up to `sh_addralign`
            // for *every* section, including NOBITS ones).
            let overflow = || ElfError::LayoutOverflow {
                section: s.section_name.clone(),
            };
            let align = usize::try_from(s.header.sh_addralign.max(1)).map_err(|_| overflow())?;
            let aligned = if align > 1 {
                cursor
                    .div_ceil(align)
                    .checked_mul(align)
                    .ok_or_else(overflow)?
            } else {
                cursor
            };
            // NOBITS: record the aligned offset but write nothing and do not
            // advance the running cursor, so the next section starts where the
            // previous one ended (byte-compatible with the reference tool).
            if matches!(
                SectionKind::from_sh_type(s.header.sh_type),
                SectionKind::Nobits
            ) {
                s.header.sh_offset = aligned as u64;
                continue;
            }
            cursor = aligned;
            s.header.sh_offset = cursor as u64;
            if !matches!(
                SectionKind::from_sh_type(s.header.sh_type),
                SectionKind::Nobits
            ) {
                s.header.sh_size = s.section_contents.len() as u64;
            }
            // Non-NOBITS here, so sh_size == section_contents.len() (fits usize).
            cursor = cursor
                .checked_add(s.section_contents.len())
                .ok_or_else(overflow)?;
        }

        // Recompute symtab sh_link to point to its strtab in the filtered list.
        // Recompute program-header entries from sections.
        let mut segments: Vec<ElfProgramHeaderEntry> = Vec::new();
        for s in &sections {
            if s.header.sh_flags & SHF_ALLOC == 0 {
                continue;
            }
            let mut seg = ElfProgramHeaderEntry::new();
            seg.p_type = match SectionKind::from_sh_type(s.header.sh_type) {
                SectionKind::Other if s.header.sh_type == ShType::SHT_DYNAMIC => p_type::PT_DYNAMIC,
                SectionKind::Other if s.header.sh_type == ShType::SHT_NOTE => p_type::PT_NOTE,
                _ => p_type::PT_LOAD,
            };
            let mut flags = p_flags::PF_R | p_flags::PF_X | p_flags::PF_W;
            if s.header.sh_flags & SHF_EXECINSTR != 0 {
                flags |= p_flags::PF_X;
            }
            if s.header.sh_flags & SHF_WRITE != 0 {
                flags |= p_flags::PF_W;
            }
            seg.p_flags = flags;
            seg.p_vaddr = s.header.sh_addr;
            seg.p_paddr = s.header.sh_addr;
            seg.p_memsz = s.header.sh_size;
            seg.p_offset = s.header.sh_offset;
            seg.p_filesz = if matches!(
                SectionKind::from_sh_type(s.header.sh_type),
                SectionKind::Nobits
            ) {
                0
            } else {
                s.header.sh_size
            };
            segments.push(seg);
        }
        if segments.is_empty() {
            return Err(ElfError::NoAllocSection);
        }

        // Program-header table goes after the section contents.
        let phoff = cursor as u64;
        header.e_phoff = phoff;
        header.e_phnum = segments.len() as u16;
        header.e_phentsize = ElfProgramHeaderEntry::entry_size(self.is_64_bits) as u16;

        // Now write the file.
        // File header.
        let mut buf: Vec<u8> = Vec::with_capacity(cursor + 1024);
        header.serialize(&mut buf)?;
        // Section headers (one slot per section, in filtered order).
        for s in &sections {
            s.header
                .serialize(&mut buf, self.is_big_endian, self.is_64_bits)?;
        }
        // Section contents, in filtered order, honoring sh_offset.
        let mut content_idxs: Vec<usize> = (0..sections.len()).collect();
        content_idxs.sort_by_key(|&i| sections[i].header.sh_offset);
        let mut last_end = buf.len();
        for &i in &content_idxs {
            let s = &sections[i];
            if matches!(
                SectionKind::from_sh_type(s.header.sh_type),
                SectionKind::Nobits
            ) {
                continue;
            }
            let target = s.header.sh_offset as usize;
            if target > last_end {
                buf.extend(std::iter::repeat(0u8).take(target - last_end));
            }
            buf.extend_from_slice(&s.section_contents);
            last_end = buf.len();
        }
        // Pad to phoff.
        if buf.len() < phoff as usize {
            buf.extend(std::iter::repeat(0u8).take(phoff as usize - buf.len()));
        }
        // Program headers.
        for seg in &segments {
            seg.serialize(&mut buf, self.is_big_endian, self.is_64_bits)?;
        }

        // Re-write sections[0]'s header with sh_offset = final file size.
        if !sections.is_empty() {
            let final_size = buf.len() as u64;
            let mut shdr = sections[0].header.clone();
            shdr.sh_offset = final_size;
            let shdr_pos = header.e_shoff as usize;
            let mut tmp: Vec<u8> = Vec::with_capacity(ElfSectionHeader::size(self.is_64_bits));
            shdr.serialize(&mut tmp, self.is_big_endian, self.is_64_bits)?;
            let end = shdr_pos + tmp.len();
            if end <= buf.len() {
                buf[shdr_pos..end].copy_from_slice(&tmp);
            }
        }

        out.write_all(&buf).map_err(ElfError::Io)
    }
}

// Suppress unused-import warnings (kept for the public re-exports below).
#[allow(unused_imports)]
use crate::enums::EType as _EType;
#[allow(unused_imports)]
use crate::enums::EiOsabi as _EiOsabi;
#[allow(unused_imports)]
use crate::enums::EiVersion as _EiVersion;
