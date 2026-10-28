// SPDX-License-Identifier: GPL-3.0-or-later
// Author: kelexine (https://github.com/kelexine)
// Rust port of marin-m/vmlinux-to-elf (https://github.com/marin-m/vmlinux-to-elf)
//
//! ELF-input pre-pass (`preprocess_elf_rela_table` in the reference tool).
//!
//! When the kernel image handed to the finder is already an ELF file (for
//! instance the output of a previous run, or a stripped `vmlinux`), the
//! `.rela.dyn` table must be applied to the section contents *before* the
//! kallsyms structures are searched: some `R_AARCH64_RELATIVE` relocations
//! patch pointers into the kallsyms tables themselves, and without them the
//! addresses read back as raw link-time offsets.
//!
//! The image is re-serialized afterwards, so file offsets reported later by
//! the finder refer to the re-laid-out ELF, exactly like the reference.

#![forbid(unsafe_code)]

use crate::error::KallsymsError;
use v2e_elf::ElfFile;

/// `R_AARCH64_RELATIVE` relocation type.
const R_AARCH64_RELATIVE: u32 = 0x403;
/// Size in bytes of the pointer-sized slot a relative relocation patches.
const PATCH_SIZE: u64 = 8;

/// Result of the pre-pass.
#[derive(Debug)]
pub struct ElfPreprocessed {
    /// The image to search (re-serialized if relocations were applied).
    pub image: Vec<u8>,
    /// `true` when a `.rela.dyn` section was found and the image was rebuilt.
    pub is_relocated: bool,
}

/// Apply `.rela.dyn` `R_AARCH64_RELATIVE` entries to an ELF image.
///
/// Inputs that do not start with the ELF magic are returned untouched with
/// `is_relocated == false`. Never panics on malformed input: a relocation that
/// points outside every section (or outside the section's stored bytes) stops
/// the pass with a warning, mirroring the reference tool.
///
/// # Errors
/// [`KallsymsError::Elf`] when the input claims to be an ELF but cannot be
/// parsed or re-serialized.
pub fn preprocess_elf_rela_table(kernel_img: Vec<u8>) -> Result<ElfPreprocessed, KallsymsError> {
    if !kernel_img.starts_with(b"\x7fELF") {
        return Ok(ElfPreprocessed {
            image: kernel_img,
            is_relocated: false,
        });
    }

    let mut kernel = ElfFile::from_bytes(&kernel_img)?;

    let Some(rela_idx) = kernel
        .sections
        .iter()
        .position(|s| s.section_name == ".rela.dyn")
    else {
        return Ok(ElfPreprocessed {
            image: kernel_img,
            is_relocated: false,
        });
    };

    // Clone the (small) table so we can mutate other sections while iterating.
    let relocations = kernel.sections[rela_idx].relocations.clone();
    let locator = kernel.section_locator();
    let mut applied: usize = 0;

    for reloc in relocations {
        if reloc.r_info_type() != R_AARCH64_RELATIVE {
            continue;
        }
        let Some(addend) = reloc.r_addend else {
            // A REL-style table has no addend; nothing sensible to apply.
            log::warn!(
                "WARNING! .rela.dyn entry without addend at {:#x}",
                reloc.r_offset
            );
            break;
        };

        let Some(sec_idx) = locator.find(reloc.r_offset) else {
            log::warn!("WARNING! bad rela offset: {:08x}", reloc.r_offset);
            break;
        };

        let section = &mut kernel.sections[sec_idx];
        let sec_addr = section.header.sh_addr;
        let sec_end = sec_addr.saturating_add(section.header.sh_size);

        let patch_off = reloc.r_offset - sec_addr; // locator guarantees r_offset >= sec_addr
        let patch_end = reloc.r_offset.saturating_add(PATCH_SIZE);
        let in_bounds = patch_end <= sec_end
            && usize::try_from(patch_off.saturating_add(PATCH_SIZE))
                .is_ok_and(|end| end <= section.section_contents.len());
        if !in_bounds {
            // Also covers NOBITS sections (no stored bytes) without panicking.
            log::warn!("WARNING! bad rela offset: {:08x}", reloc.r_offset);
            break;
        }

        // `in_bounds` proved both conversions and the slice range are valid.
        let start = patch_off as usize;
        let slot = &mut section.section_contents[start..start + PATCH_SIZE as usize];
        let mut raw = [0u8; 8];
        raw.copy_from_slice(slot);
        // The reference reads and writes these slots little-endian.
        let patched = u64::from_le_bytes(raw).wrapping_add(addend as u64);
        slot.copy_from_slice(&patched.to_le_bytes());
        applied += 1;
    }

    log::debug!("[+] Pre-applied {applied} R_AARCH64_RELATIVE relocations from the input ELF");

    let mut image = Vec::with_capacity(kernel_img.len());
    kernel.serialize(&mut image)?;
    Ok(ElfPreprocessed {
        image,
        is_relocated: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_elf_input_is_passed_through() {
        let raw = b"not an elf at all".to_vec();
        let out = preprocess_elf_rela_table(raw.clone()).unwrap();
        assert_eq!(out.image, raw);
        assert!(!out.is_relocated);
    }

    #[test]
    fn truncated_elf_is_an_error_not_a_panic() {
        let err = preprocess_elf_rela_table(b"\x7fELF\x02\x01".to_vec()).unwrap_err();
        assert!(matches!(err, KallsymsError::Elf(_)));
    }

    #[test]
    fn empty_input_is_passed_through() {
        let out = preprocess_elf_rela_table(Vec::new()).unwrap();
        assert!(out.image.is_empty());
        assert!(!out.is_relocated);
    }
}
