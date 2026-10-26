// SPDX-License-Identifier: GPL-3.0-or-later

//! ELF enumerations: SH_TYPE, SH_FLAGS, ST_INFO_*, SPECIAL_*_INDEX, EI_*, E_TYPE.

#![forbid(unsafe_code)]

/// `SH_TYPE` — section header types.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum ShType {
    /// `SHT_NULL = 0`.
    SHT_NULL = 0,
    /// `SHT_PROGBITS = 1`.
    SHT_PROGBITS = 1,
    /// `SHT_SYMTAB = 2`.
    SHT_SYMTAB = 2,
    /// `SHT_STRTAB = 3`.
    SHT_STRTAB = 3,
    /// `SHT_RELA = 4`.
    SHT_RELA = 4,
    /// `SHT_HASH = 5`.
    SHT_HASH = 5,
    /// `SHT_DYNAMIC = 6`.
    SHT_DYNAMIC = 6,
    /// `SHT_NOTE = 7`.
    SHT_NOTE = 7,
    /// `SHT_NOBITS = 8`.
    SHT_NOBITS = 8,
    /// `SHT_REL = 9`.
    SHT_REL = 9,
    /// `SHT_SHLIB = 10`.
    SHT_SHLIB = 10,
    /// `SHT_DYNSYM = 11`.
    SHT_DYNSYM = 11,
    /// `SHT_INIT_ARRAY = 14`.
    SHT_INIT_ARRAY = 14,
    /// `SHT_FINI_ARRAY = 15`.
    SHT_FINI_ARRAY = 15,
    /// `SHT_PREINIT_ARRAY = 16`.
    SHT_PREINIT_ARRAY = 16,
    /// `SHT_GROUP = 17`.
    SHT_GROUP = 17,
    /// `SHT_SYMTAB_SHNDX = 18`.
    SHT_SYMTAB_SHNDX = 18,
    /// `SHT_NUM = 19`.
    SHT_NUM = 19,
    /// `SHT_GNU_ATTRIBUTES = 0x6FFFFFF5`.
    SHT_GNU_ATTRIBUTES = 0x6FFFFFF5,
    /// `SHT_GNU_HASH = 0x6FFFFFF6`.
    SHT_GNU_HASH = 0x6FFFFFF6,
    /// `SHT_GNU_LIBLIST = 0x6FFFFFF7`.
    SHT_GNU_LIBLIST = 0x6FFFFFF7,
    /// `SHT_GNU_VERDEF = 0x6FFFFFFD`.
    SHT_GNU_VERDEF = 0x6FFFFFFD,
    /// `SHT_GNU_VERNEED = 0x6FFFFFFE`.
    SHT_GNU_VERNEED = 0x6FFFFFFE,
    /// `SHT_GNU_VERSYM = 0x6FFFFFFF`.
    SHT_GNU_VERSYM = 0x6FFFFFFF,
    /// `SHT_MIPS_REGINFO = 0x70000006`.
    SHT_MIPS_REGINFO = 0x70000006,
    /// `SHT_MIPS_ABIFLAGS = 0x7000002A`.
    SHT_MIPS_ABIFLAGS = 0x7000002A,
    /// `SHT_ANDROID_RELR = 0x6FFFFF00`.
    SHT_ANDROID_RELR = 0x6FFFFF00,
    /// Catch-all for any other section type encountered.
    Other(u32),
}

impl ShType {
    /// Construct from a raw `u32`. Known values become named variants;
    /// unknown values become `Other(v)`.
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => ShType::SHT_NULL,
            1 => ShType::SHT_PROGBITS,
            2 => ShType::SHT_SYMTAB,
            3 => ShType::SHT_STRTAB,
            4 => ShType::SHT_RELA,
            5 => ShType::SHT_HASH,
            6 => ShType::SHT_DYNAMIC,
            7 => ShType::SHT_NOTE,
            8 => ShType::SHT_NOBITS,
            9 => ShType::SHT_REL,
            10 => ShType::SHT_SHLIB,
            11 => ShType::SHT_DYNSYM,
            14 => ShType::SHT_INIT_ARRAY,
            15 => ShType::SHT_FINI_ARRAY,
            16 => ShType::SHT_PREINIT_ARRAY,
            17 => ShType::SHT_GROUP,
            18 => ShType::SHT_SYMTAB_SHNDX,
            19 => ShType::SHT_NUM,
            0x6FFFFFF5 => ShType::SHT_GNU_ATTRIBUTES,
            0x6FFFFFF6 => ShType::SHT_GNU_HASH,
            0x6FFFFFF7 => ShType::SHT_GNU_LIBLIST,
            0x6FFFFFFD => ShType::SHT_GNU_VERDEF,
            0x6FFFFFFE => ShType::SHT_GNU_VERNEED,
            0x6FFFFFFF => ShType::SHT_GNU_VERSYM,
            0x70000006 => ShType::SHT_MIPS_REGINFO,
            0x7000002A => ShType::SHT_MIPS_ABIFLAGS,
            0x6FFFFF00 => ShType::SHT_ANDROID_RELR,
            other => ShType::Other(other),
        }
    }

    /// Convert to raw `u32`.
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        match self {
            ShType::SHT_NULL => 0,
            ShType::SHT_PROGBITS => 1,
            ShType::SHT_SYMTAB => 2,
            ShType::SHT_STRTAB => 3,
            ShType::SHT_RELA => 4,
            ShType::SHT_HASH => 5,
            ShType::SHT_DYNAMIC => 6,
            ShType::SHT_NOTE => 7,
            ShType::SHT_NOBITS => 8,
            ShType::SHT_REL => 9,
            ShType::SHT_SHLIB => 10,
            ShType::SHT_DYNSYM => 11,
            ShType::SHT_INIT_ARRAY => 14,
            ShType::SHT_FINI_ARRAY => 15,
            ShType::SHT_PREINIT_ARRAY => 16,
            ShType::SHT_GROUP => 17,
            ShType::SHT_SYMTAB_SHNDX => 18,
            ShType::SHT_NUM => 19,
            ShType::SHT_GNU_ATTRIBUTES => 0x6FFFFFF5,
            ShType::SHT_GNU_HASH => 0x6FFFFFF6,
            ShType::SHT_GNU_LIBLIST => 0x6FFFFFF7,
            ShType::SHT_GNU_VERDEF => 0x6FFFFFFD,
            ShType::SHT_GNU_VERNEED => 0x6FFFFFFE,
            ShType::SHT_GNU_VERSYM => 0x6FFFFFFF,
            ShType::SHT_MIPS_REGINFO => 0x70000006,
            ShType::SHT_MIPS_ABIFLAGS => 0x7000002A,
            ShType::SHT_ANDROID_RELR => 0x6FFFFF00,
            ShType::Other(v) => v,
        }
    }
}

/// `SH_FLAGS` bitmask values. Mirror of `SH_FLAGS(IntEnum)`.
pub mod sh_flags {
    /// `SHF_WRITE = 0x1`.
    pub const SHF_WRITE: u64 = 0x1;
    /// `SHF_ALLOC = 0x2`.
    pub const SHF_ALLOC: u64 = 0x2;
    /// `SHF_EXECINSTR = 0x4`.
    pub const SHF_EXECINSTR: u64 = 0x4;
}

/// `ST_INFO_TYPE` — symbol type (low 4 bits of `st_info`).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum StInfoType {
    /// `STT_NOTYPE = 0`.
    STT_NOTYPE = 0,
    /// `STT_OBJECT = 1`.
    STT_OBJECT = 1,
    /// `STT_FUNC = 2`.
    STT_FUNC = 2,
    /// `STT_SECTION = 3`.
    STT_SECTION = 3,
    /// `STT_FILE = 4`.
    STT_FILE = 4,
}

impl StInfoType {
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => StInfoType::STT_NOTYPE,
            1 => StInfoType::STT_OBJECT,
            2 => StInfoType::STT_FUNC,
            3 => StInfoType::STT_SECTION,
            4 => StInfoType::STT_FILE,
            _ => StInfoType::STT_NOTYPE,
        }
    }
}

/// `ST_INFO_BINDING` — symbol binding (high 4 bits of `st_info`).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum StInfoBinding {
    /// `STB_LOCAL = 0`.
    STB_LOCAL = 0,
    /// `STB_GLOBAL = 1`.
    STB_GLOBAL = 1,
    /// `STB_WEAK = 2`.
    STB_WEAK = 2,
}

impl StInfoBinding {
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => StInfoBinding::STB_LOCAL,
            1 => StInfoBinding::STB_GLOBAL,
            2 => StInfoBinding::STB_WEAK,
            _ => StInfoBinding::STB_LOCAL,
        }
    }
}

/// `SPECIAL_SECTION_INDEX` — well-known reserved section indices.
pub mod special_section_index {
    /// `SHN_UNDEF = 0`.
    pub const SHN_UNDEF: u16 = 0;
    /// `SHN_LORESERVE = 0xFF00`.
    pub const SHN_LORESERVE: u16 = 0xFF00;
    /// `SHN_LOPROC = 0xFF00`.
    pub const SHN_LOPROC: u16 = 0xFF00;
    /// `SHN_HIPROC = 0xFF1F`.
    pub const SHN_HIPROC: u16 = 0xFF1F;
    /// `SHN_LIVEPATCH = 0xFF20`.
    pub const SHN_LIVEPATCH: u16 = 0xFF20;
    /// `SHN_ABS = 0xFFF1`.
    pub const SHN_ABS: u16 = 0xFFF1;
    /// `SHN_COMMON = 0xFFF2`.
    pub const SHN_COMMON: u16 = 0xFFF2;
    /// `SHN_HIRESERVE = 0xFFFF`.
    pub const SHN_HIRESERVE: u16 = 0xFFFF;
    /// `SHN_XINDEX = 0xFFFF`.
    pub const SHN_XINDEX: u16 = 0xFFFF;
}

/// `SPECIAL_SEGMENT_INDEX`.
pub mod special_segment_index {
    /// `PN_XNUM = 0xFFFF`.
    pub const PN_XNUM: u16 = 0xFFFF;
}

/// `E_IDENT_INDEXES` — byte offsets within `e_ident`.
pub mod e_ident_indexes {
    /// `EI_MAG0 = 0`.
    pub const EI_MAG0: usize = 0;
    /// `EI_MAG1 = 1`.
    pub const EI_MAG1: usize = 1;
    /// `EI_MAG2 = 2`.
    pub const EI_MAG2: usize = 2;
    /// `EI_MAG3 = 3`.
    pub const EI_MAG3: usize = 3;
    /// `EI_CLASS = 4`.
    pub const EI_CLASS: usize = 4;
    /// `EI_DATA = 5`.
    pub const EI_DATA: usize = 5;
    /// `EI_VERSION = 6`.
    pub const EI_VERSION: usize = 6;
    /// `EI_OSABI = 7`.
    pub const EI_OSABI: usize = 7;
    /// `EI_ABIVERSION = 8`.
    pub const EI_ABIVERSION: usize = 8;
    /// `EI_NIDENT = 16`.
    pub const EI_NIDENT: usize = 16;
}

/// `EI_CLASS` byte values.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum EiClass {
    /// `ELFCLASS32 = 1`.
    ELFCLASS32 = 1,
    /// `ELFCLASS64 = 2`.
    ELFCLASS64 = 2,
}

impl EiClass {
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(EiClass::ELFCLASS32),
            2 => Some(EiClass::ELFCLASS64),
            _ => None,
        }
    }
}

/// `EI_DATA` byte values.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum EiData {
    /// `ELFDATA2LSB = 1` (little-endian).
    ELFDATA2LSB = 1,
    /// `ELFDATA2MSB = 2` (big-endian).
    ELFDATA2MSB = 2,
}

impl EiData {
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(EiData::ELFDATA2LSB),
            2 => Some(EiData::ELFDATA2MSB),
            _ => None,
        }
    }
}

/// `EI_VERSION`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum EiVersion {
    /// `EV_CURRENT = 1`.
    EV_CURRENT = 1,
}

/// `EI_OSABI`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum EiOsabi {
    /// `ELFOSABI_SYSV = 0`.
    ELFOSABI_SYSV = 0,
    /// `ELFOSABI_HPUX = 1`.
    ELFOSABI_HPUX = 1,
    /// `ELFOSABI_STANDALONE = 255`.
    ELFOSABI_STANDALONE = 255,
}

/// `E_TYPE` — ELF file type.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum EType {
    /// `ET_NONE = 0`.
    ET_NONE = 0,
    /// `ET_REL = 1` — relocatable.
    ET_REL = 1,
    /// `ET_EXEC = 2` — executable.
    ET_EXEC = 2,
    /// `ET_DYN = 3` — shared object.
    ET_DYN = 3,
    /// `ET_CORE = 4` — core dump.
    ET_CORE = 4,
}

impl EType {
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        self as u16
    }
}

/// `P_TYPE` — program header types.
pub mod p_type {
    /// `PT_NULL = 0`.
    pub const PT_NULL: u32 = 0;
    /// `PT_LOAD = 1`.
    pub const PT_LOAD: u32 = 1;
    /// `PT_DYNAMIC = 2`.
    pub const PT_DYNAMIC: u32 = 2;
    /// `PT_INTERP = 3`.
    pub const PT_INTERP: u32 = 3;
    /// `PT_NOTE = 4`.
    pub const PT_NOTE: u32 = 4;
    /// `PT_SHLIB = 5`.
    pub const PT_SHLIB: u32 = 5;
    /// `PT_PHDR = 6`.
    pub const PT_PHDR: u32 = 6;
}

/// `P_FLAGS` bitmask values.
pub mod p_flags {
    /// `PF_X = 0x1`.
    pub const PF_X: u32 = 0x1;
    /// `PF_W = 0x2`.
    pub const PF_W: u32 = 0x2;
    /// `PF_R = 0x4`.
    pub const PF_R: u32 = 0x4;
}
