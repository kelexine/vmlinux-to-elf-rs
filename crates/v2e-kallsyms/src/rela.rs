// SPDX-License-Identifier: GPL-3.0-or-later
//
//! ARM64 ELF64 RELA scan + apply.
//!
//! `find_elf64_rela` and `apply_elf64_rela`
//!
//! - The `R_AARCH64_ABS64 = 0x101` / `R_AARCH64_RELATIVE = 0x403` filter.
//! - The `(0,0,0)` empty-ent-skip + "longest contiguous run ≥ 1000" rule.
//! - The addend-based kernel-text-candidate inference.
//! - The kallsyms-region overlap guard.

#![forbid(unsafe_code)]

/// A single decoded `Elf64_Rela` entry.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Elf64Rela {
    /// `r_offset` (where to patch).
    pub r_offset: u64,
    /// `r_info` (full 64-bit; low 32 bits = type).
    pub r_info: u64,
    /// `r_addend`.
    pub r_addend: i64,
}

impl Elf64Rela {
    /// Extract the relocation type from `r_info` (low 32 bits).
    #[must_use]
    #[inline]
    pub const fn r_info_type(self) -> u32 {
        (self.r_info & 0xFFFF_FFFF) as u32
    }

    /// Extract the symbol index from `r_info` (high 32 bits).
    #[must_use]
    #[inline]
    pub const fn r_info_sym(self) -> u32 {
        (self.r_info >> 32) as u32
    }
}

/// `R_AARCH64_ABS64 = 0x101`.
pub const R_AARCH64_ABS64: u32 = 0x101;
/// `R_AARCH64_RELATIVE = 0x403`.
pub const R_AARCH64_RELATIVE: u32 = 0x403;
/// `rela64_size = 24` (3 × u64).
pub const RELA64_SIZE: usize = 24;
/// Minimum contiguous run length to accept as a RELA table.
pub const MINIMAL_HEURISTIC_COUNT: usize = 1000;
/// Minimum kernel VA we accept for addend-based base inference.
pub const MINIMAL_KERNEL_VA: u64 = 0xFFFF_C000_8000_0000;
