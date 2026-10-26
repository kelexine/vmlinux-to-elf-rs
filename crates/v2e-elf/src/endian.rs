// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Endianness + word-size enums and tiny cursor helpers used by all ELF structure readers/writers.

#![forbid(unsafe_code)]

/// Byte order of an ELF object.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Endianness {
    /// Little-endian (`ELFDATA2LSB`, `EI_DATA == 1`).
    Little,
    /// Big-endian (`ELFDATA2MSB`, `EI_DATA == 2`).
    Big,
}

impl Endianness {
    /// Read a `u16` from `bytes` using this endianness. Bounds-checking is the caller's responsibility.
    #[must_use]
    #[inline]
    pub fn read_u16(self, bytes: &[u8]) -> u16 {
        match self {
            Endianness::Little => u16::from_le_bytes([bytes[0], bytes[1]]),
            Endianness::Big => u16::from_be_bytes([bytes[0], bytes[1]]),
        }
    }

    /// Read a `u32` from `bytes` using this endianness.
    #[must_use]
    #[inline]
    pub fn read_u32(self, bytes: &[u8]) -> u32 {
        match self {
            Endianness::Little => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            Endianness::Big => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        }
    }

    /// Read a `u64` from `bytes` using this endianness.
    #[must_use]
    #[inline]
    pub fn read_u64(self, bytes: &[u8]) -> u64 {
        match self {
            Endianness::Little => u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            Endianness::Big => u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
        }
    }

    /// Read a signed `i32` from `bytes` using this endianness.
    #[must_use]
    #[inline]
    pub fn read_i32(self, bytes: &[u8]) -> i32 {
        match self {
            Endianness::Little => i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            Endianness::Big => i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        }
    }

    /// Read a signed `i64` from `bytes` using this endianness.
    #[must_use]
    #[inline]
    pub fn read_i64(self, bytes: &[u8]) -> i64 {
        match self {
            Endianness::Little => i64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            Endianness::Big => i64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
        }
    }

    /// Write a `u16` to `dst` using this endianness.
    #[inline]
    pub fn write_u16(self, dst: &mut [u8], value: u16) {
        match self {
            Endianness::Little => dst[..2].copy_from_slice(&value.to_le_bytes()),
            Endianness::Big => dst[..2].copy_from_slice(&value.to_be_bytes()),
        }
    }

    /// Write a `u32` to `dst` using this endianness.
    #[inline]
    pub fn write_u32(self, dst: &mut [u8], value: u32) {
        match self {
            Endianness::Little => dst[..4].copy_from_slice(&value.to_le_bytes()),
            Endianness::Big => dst[..4].copy_from_slice(&value.to_be_bytes()),
        }
    }

    /// Write a `u64` to `dst` using this endianness.
    #[inline]
    pub fn write_u64(self, dst: &mut [u8], value: u64) {
        match self {
            Endianness::Little => dst[..8].copy_from_slice(&value.to_le_bytes()),
            Endianness::Big => dst[..8].copy_from_slice(&value.to_be_bytes()),
        }
    }
}

/// Word size of an ELF object. Maps 1-to-1 to `EI_CLASS`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum BitSize {
    /// 32-bit (`ELFCLASS32`, `EI_CLASS == 1`).
    Bits32,
    /// 64-bit (`ELFCLASS64`, `EI_CLASS == 2`).
    Bits64,
}

impl BitSize {
    /// Returns `true` for 64-bit ELF objects.
    #[must_use]
    #[inline]
    pub const fn is_64(self) -> bool {
        matches!(self, BitSize::Bits64)
    }

    /// Returns the size in bytes of an `Elf*_Addr` / `Elf*_Off` / `Elf*_Xword`.
    #[must_use]
    #[inline]
    pub const fn addr_size(self) -> usize {
        match self {
            BitSize::Bits32 => 4,
            BitSize::Bits64 => 8,
        }
    }
}
