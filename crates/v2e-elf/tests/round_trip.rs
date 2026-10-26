// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Round-trip tests for `v2e-elf`

#![forbid(unsafe_code)]

use std::fs;
use v2e_elf::{ElfFile, ElfFileHeader};

const FIXTURES: &[(&str, &str)] = &[
    ("ls_x64.elf", "ELF64 little-endian"),
    ("ls_arm32_le.elf", "ELF32 little-endian ARM"),
    ("ls_mips32_le.elf", "ELF32 little-endian MIPS"),
    ("ls_mips32_be.elf", "ELF32 big-endian MIPS"),
    ("ls_mips64_be.elf", "ELF64 big-endian MIPS"),
    ("x86_shared_library.so", "ELF x86 shared object"),
];

fn fixture_path(name: &str) -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../tests/fixtures/elf_tests");
    p.push(name);
    p
}

#[test]
fn parse_each_fixture_succeeds() {
    for (name, desc) in FIXTURES {
        let path = fixture_path(name);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("skip {name} ({desc}): {e}");
                continue;
            },
        };
        match ElfFile::from_bytes(&bytes) {
            Ok(elf) => {
                let n_sections = elf.sections.len();
                let n_segments = elf.segments.len();
                println!("ok {name} ({desc}): {n_sections} sections, {n_segments} segments");
            },
            Err(e) => panic!("parse {name} ({desc}) failed: {e}"),
        }
    }
}

#[test]
fn header_round_trips_for_each_fixture() {
    for (name, _desc) in FIXTURES {
        let path = fixture_path(name);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let original_header = match ElfFileHeader::parse(&bytes) {
            Ok(h) => h,
            Err(e) => panic!("header parse {name}: {e}"),
        };
        let mut out: Vec<u8> = Vec::with_capacity(original_header.size());
        original_header
            .serialize(&mut out)
            .expect("serialize header");
        let re_parsed = ElfFileHeader::parse(&out).expect("re-parse header");
        assert_eq!(
            original_header.ei_class, re_parsed.ei_class,
            "{name}: ei_class"
        );
        assert_eq!(
            original_header.ei_data, re_parsed.ei_data,
            "{name}: ei_data"
        );
        assert_eq!(
            original_header.e_machine, re_parsed.e_machine,
            "{name}: e_machine"
        );
        assert_eq!(original_header.e_type, re_parsed.e_type, "{name}: e_type");
        assert_eq!(
            original_header.e_entry, re_parsed.e_entry,
            "{name}: e_entry"
        );
    }
}

#[test]
fn section_headers_round_trip() {
    for (name, _desc) in FIXTURES {
        let path = fixture_path(name);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let elf = ElfFile::from_bytes(&bytes).expect("parse");
        for s in &elf.sections {
            let mut out: Vec<u8> = Vec::new();
            s.header
                .serialize(&mut out, elf.is_big_endian, elf.is_64_bits)
                .expect("serialize shdr");
            assert_eq!(out.len(), v2e_elf::ElfSectionHeader::size(elf.is_64_bits));
        }
    }
}
