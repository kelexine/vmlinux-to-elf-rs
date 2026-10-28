// SPDX-License-Identifier: GPL-3.0-or-later
// Author: kelexine (https://github.com/kelexine)
// Rust port of marin-m/vmlinux-to-elf (https://github.com/marin-m/vmlinux-to-elf)
//
//! Behavioral tests for [`SectionLocator`] and `ElfFile::serialize` layout.
//!
//! These pin the exact rules of the reference implementation that the first
//! port got wrong (boundary-symbol section choice and NOBITS offsets).

#![forbid(unsafe_code)]

use v2e_elf::{BitSize, ElfError, ElfFile, ElfSection, Endianness, SectionKind, ShType, sh_flags};

fn section(kind: SectionKind, name: &str, addr: u64, size: u64, align: u64) -> ElfSection {
    let mut s = ElfSection::new(kind, name, Endianness::Little, BitSize::Bits64);
    s.header.sh_addr = addr;
    s.header.sh_size = size;
    s.header.sh_addralign = align;
    s.header.sh_flags = sh_flags::SHF_ALLOC;
    s
}

fn progbits(name: &str, addr: u64, contents: &[u8], align: u64) -> ElfSection {
    let mut s = section(
        SectionKind::Progbits,
        name,
        addr,
        contents.len() as u64,
        align,
    );
    s.section_contents = contents.to_vec();
    s
}

/// NULL + user sections + `.shstrtab`, ready to serialize.
fn elf_with(sections: Vec<ElfSection>) -> ElfFile {
    let mut elf = ElfFile::new(Endianness::Little, BitSize::Bits64);
    elf.sections.push(ElfSection::new(
        SectionKind::Null,
        "",
        Endianness::Little,
        BitSize::Bits64,
    ));
    elf.sections.extend(sections);
    let mut shstr = ElfSection::new(
        SectionKind::Strtab,
        ".shstrtab",
        Endianness::Little,
        BitSize::Bits64,
    );
    shstr.header.sh_flags = 0;
    elf.sections.push(shstr);
    elf.section_string_table_index = Some(elf.sections.len() - 1);
    elf
}

fn locator_of(sections: Vec<ElfSection>) -> (ElfFile, v2e_elf::SectionLocator) {
    let elf = elf_with(sections);
    let loc = elf.section_locator();
    (elf, loc)
}

#[test]
fn boundary_address_resolves_to_the_section_that_starts_there() {
    // .a = [0x1000, 0x2000], .b starts exactly at 0x2000.
    let (elf, loc) = locator_of(vec![
        progbits(".a", 0x1000, &[0; 0x1000], 1),
        progbits(".b", 0x2000, &[0; 0x1000], 1),
    ]);
    let a = elf.sections.iter().position(|s| s.section_name == ".a");
    let b = elf.sections.iter().position(|s| s.section_name == ".b");
    assert_eq!(
        loc.find(0x2000),
        b,
        "boundary must prefer the section that starts here"
    );
    assert_eq!(loc.find(0x1fff), a);
    assert_eq!(loc.find(0x1000), a);
}

#[test]
fn end_bound_is_inclusive_and_gaps_are_unresolved() {
    let (elf, loc) = locator_of(vec![progbits(".a", 0x1000, &[0; 0x10], 1)]);
    let a = elf.sections.iter().position(|s| s.section_name == ".a");
    assert_eq!(
        loc.find(0x1010),
        a,
        "address == sh_addr + sh_size is still inside"
    );
    assert_eq!(
        loc.find(0x1011),
        None,
        "one past the inclusive end is a miss"
    );
    assert_eq!(loc.find(0x0fff), None, "below every section");
    assert_eq!(loc.find(u64::MAX), None, "no overflow on huge addresses");
}

#[test]
fn zero_address_sections_are_ignored_and_ties_pick_the_last_declared() {
    let (elf, loc) = locator_of(vec![
        progbits(".unmapped", 0, &[0; 8], 1),
        progbits(".first", 0x3000, &[0; 8], 1),
        progbits(".second", 0x3000, &[0; 8], 1),
    ]);
    let second = elf
        .sections
        .iter()
        .position(|s| s.section_name == ".second");
    assert_eq!(loc.find(0x3004), second);
    assert_eq!(loc.find(0), None);
}

#[test]
fn locator_on_an_empty_file_never_panics() {
    let elf = ElfFile::new(Endianness::Little, BitSize::Bits64);
    assert_eq!(elf.section_locator().find(0x1234), None);
    assert_eq!(elf.find_section_index(0), None);
}

#[test]
fn nobits_offset_is_aligned_but_does_not_advance_the_cursor() {
    let bss = section(SectionKind::Nobits, ".bss", 0x9000, 0x4000, 0x1000);
    let elf = elf_with(vec![
        progbits(".text", 0x1000, &[0xAA; 5], 1),
        bss,
        progbits(".tail", 0x20000, &[0xBB; 3], 1),
    ]);
    let mut out = Vec::new();
    elf.serialize(&mut out).expect("serialize");
    let back = ElfFile::from_bytes(&out).expect("re-parse");
    let by_name = |n: &str| {
        back.sections
            .iter()
            .find(|s| s.section_name == n)
            .unwrap_or_else(|| panic!("section {n} missing after round-trip"))
            .header
            .clone()
    };
    let (text, bss, tail) = (by_name(".text"), by_name(".bss"), by_name(".tail"));

    assert_eq!(
        bss.sh_offset % 0x1000,
        0,
        "NOBITS offset honours sh_addralign"
    );
    assert!(bss.sh_offset >= text.sh_offset + 5);
    assert_eq!(
        tail.sh_offset,
        text.sh_offset + 5,
        "the next section starts right after the last real content"
    );
    assert_eq!(bss.sh_type, ShType::SHT_NOBITS);
}

#[test]
fn non_power_of_two_alignment_is_respected() {
    let elf = elf_with(vec![progbits(".odd", 0x1000, &[1, 2, 3], 24)]);
    let mut out = Vec::new();
    elf.serialize(&mut out).expect("serialize");
    let back = ElfFile::from_bytes(&out).expect("re-parse");
    let odd = back
        .sections
        .iter()
        .find(|s| s.section_name == ".odd")
        .expect(".odd present");
    assert_eq!(odd.header.sh_offset % 24, 0);
    assert_eq!(odd.section_contents, vec![1, 2, 3]);
}

#[test]
fn hostile_alignment_is_an_error_not_a_panic_or_a_wrap() {
    let elf = elf_with(vec![progbits(".evil", 0x1000, &[1, 2, 3], u64::MAX)]);
    let mut out = Vec::new();
    let err = elf.serialize(&mut out).expect_err("must be rejected");
    assert!(
        matches!(err, ElfError::LayoutOverflow { .. }),
        "unexpected error: {err}"
    );
}
