// SPDX-License-Identifier: GPL-3.0-or-later
//
//! set as `binwalk`'s `binarch` magic file), tallies matches per
//! architecture, and returns the one with the most hits — provided the
//! count is at least 100. A secondary `_guess_architecture_special` path
//! detects UEFI boot stubs via the `MZ` + `ARMd` magic pair.

#![forbid(unsafe_code)]
#![allow(missing_docs)]
#![warn(missing_docs)]

pub mod arch;
pub use arch::{
    ArchitectureDetectionResult, ArchitectureDetector, ArchitectureGuessError, ArchitectureName,
};

pub mod elf_machine;
pub use elf_machine::ElfMachine;

pub mod arm64_efi;
pub use arm64_efi::{LinuxArm64EfiStub, SectionTableEntry as PeSectionTableEntry};

pub mod prologues;
