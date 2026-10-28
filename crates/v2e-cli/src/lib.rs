// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `v2e-cli` library — common helpers shared by the three binaries.

#![forbid(unsafe_code)]
#![allow(missing_docs)]

pub mod db;
pub mod logging;
pub mod pretty;
pub mod symbolizer;

pub use v2e_elf::section::SectionKind;

/// Helper to construct a `SectionKind` from a `ShType`.
#[must_use]
pub fn section_kind_for(ty: v2e_elf::ShType) -> SectionKind {
    SectionKind::from_sh_type(ty)
}
