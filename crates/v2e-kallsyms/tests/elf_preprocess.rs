// SPDX-License-Identifier: GPL-3.0-or-later
// Author: kelexine (https://github.com/kelexine)
// Rust port of marin-m/vmlinux-to-elf (https://github.com/marin-m/vmlinux-to-elf)
//
//! End-to-end tests for the ELF-input relocation pre-pass.

#![forbid(unsafe_code)]

use v2e_elf::{BitSize, ElfFile, ElfSection, Endianness, SectionKind, sh_flags};
use v2e_kallsyms::elf_preprocess::preprocess_elf_rela_table;

const DATA_ADDR: u64 = 0xffff_0000_0000_1000;
const R_AARCH64_RELATIVE: u64 = 0x403;
const R_AARCH64_GLOB_DAT: u64 = 0x401;

fn rela_bytes(entries: &[(u64, u64, i64)]) -> Vec<u8> {
    let mut v = Vec::new();
    for &(off, info, addend) in entries {
        v.extend_from_slice(&off.to_le_bytes());
        v.extend_from_slice(&info.to_le_bytes());
        v.extend_from_slice(&addend.to_le_bytes());
    }
    v
}

fn build_elf(data: &[u8], rela: Option<&[(u64, u64, i64)]>) -> Vec<u8> {
    let (le, b64) = (Endianness::Little, BitSize::Bits64);
    let mut elf = ElfFile::new(le, b64);
    elf.file_header.e_machine = 183; // EM_AARCH64
    elf.sections
        .push(ElfSection::new(SectionKind::Null, "", le, b64));

    let mut d = ElfSection::new(SectionKind::Progbits, ".data", le, b64);
    d.header.sh_addr = DATA_ADDR;
    d.header.sh_flags = sh_flags::SHF_ALLOC | sh_flags::SHF_WRITE;
    d.header.sh_addralign = 8;
    d.header.sh_size = data.len() as u64;
    d.section_contents = data.to_vec();
    elf.sections.push(d);

    if let Some(entries) = rela {
        let mut r = ElfSection::new(SectionKind::Rela, ".rela.dyn", le, b64);
        r.section_contents = rela_bytes(entries);
        r.header.sh_size = r.section_contents.len() as u64;
        r.header.sh_addralign = 8;
        elf.sections.push(r);
    }

    let mut shstr = ElfSection::new(SectionKind::Strtab, ".shstrtab", le, b64);
    shstr.header.sh_flags = 0;
    elf.sections.push(shstr);
    elf.section_string_table_index = Some(elf.sections.len() - 1);

    let mut out = Vec::new();
    elf.serialize(&mut out).expect("serialize fixture");
    out
}

fn data_slot(image: &[u8], at: usize) -> u64 {
    let elf = ElfFile::from_bytes(image).expect("re-parse");
    let data = elf
        .sections
        .iter()
        .find(|s| s.section_name == ".data")
        .expect(".data present");
    u64::from_le_bytes(data.section_contents[at..at + 8].try_into().unwrap())
}

#[test]
fn relative_relocations_are_applied_little_endian_with_wrapping_addend() {
    let mut data = vec![0u8; 24];
    data[0..8].copy_from_slice(&0x10u64.to_le_bytes()); // pre-existing value is added to
    let img = build_elf(
        &data,
        Some(&[
            (DATA_ADDR, R_AARCH64_RELATIVE, 0x1000),
            (DATA_ADDR + 8, R_AARCH64_RELATIVE, -1), // wraps to u64::MAX
            (DATA_ADDR + 16, R_AARCH64_GLOB_DAT, 0x77), // other types are ignored
        ]),
    );

    let out = preprocess_elf_rela_table(img).expect("preprocess");
    assert!(out.is_relocated);
    assert_eq!(data_slot(&out.image, 0), 0x1010);
    assert_eq!(data_slot(&out.image, 8), u64::MAX);
    assert_eq!(
        data_slot(&out.image, 16),
        0,
        "non-RELATIVE entries must not patch"
    );
}

#[test]
fn bad_offset_stops_the_pass_without_panicking_and_keeps_earlier_patches() {
    let img = build_elf(
        &[0u8; 16],
        Some(&[
            (DATA_ADDR, R_AARCH64_RELATIVE, 5),
            (0xdead_beef_0000, R_AARCH64_RELATIVE, 9), // outside every section -> stop
            (DATA_ADDR + 8, R_AARCH64_RELATIVE, 7),    // never reached
        ]),
    );
    let out = preprocess_elf_rela_table(img).expect("preprocess");
    assert!(out.is_relocated);
    assert_eq!(data_slot(&out.image, 0), 5);
    assert_eq!(
        data_slot(&out.image, 8),
        0,
        "pass must stop at the first bad entry"
    );
}

#[test]
fn slot_straddling_the_section_end_is_rejected_not_read_out_of_bounds() {
    // 12-byte section: an 8-byte slot at +8 would run 4 bytes past the end.
    let img = build_elf(&[0u8; 12], Some(&[(DATA_ADDR + 8, R_AARCH64_RELATIVE, 1)]));
    let out = preprocess_elf_rela_table(img).expect("preprocess");
    assert_eq!(data_slot(&out.image, 0), 0);
}

#[test]
fn elf_without_rela_dyn_is_left_alone() {
    let img = build_elf(&[1u8; 8], None);
    let out = preprocess_elf_rela_table(img.clone()).expect("preprocess");
    assert!(!out.is_relocated);
    assert_eq!(out.image, img, "no rebuild when there is nothing to apply");
}
