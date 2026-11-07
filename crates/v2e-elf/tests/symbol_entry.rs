// SPDX-License-Identifier: GPL-3.0-or-later

//! `st_info` is one byte, `(binding << 4) | type`, in every byte order.
//!
//! An earlier version swapped the nibbles when writing ELF32 big-endian
//! symbols, so every symbol in big-endian output (MIPS, PowerPC, ...) had the
//! wrong type and binding (`printk` came out as `OBJECT WEAK`, not
//! `FUNC GLOBAL`). These tests pin the encoding for all four layouts.

#![forbid(unsafe_code)]

use v2e_elf::{BitSize, Endianness, StInfoBinding, StInfoType, SymbolEntry};

const LAYOUTS: [(Endianness, BitSize); 4] = [
    (Endianness::Little, BitSize::Bits32),
    (Endianness::Big, BitSize::Bits32),
    (Endianness::Little, BitSize::Bits64),
    (Endianness::Big, BitSize::Bits64),
];

fn entry(kind: StInfoType, bind: StInfoBinding) -> SymbolEntry {
    let mut s = SymbolEntry::default();
    s.st_name = 7;
    s.st_value = 0x8010_0000;
    s.st_size = 44;
    s.st_info_type = kind;
    s.st_info_binding = bind;
    s.st_shndx = 3;
    s
}

/// Offset of the `st_info` byte inside one serialized entry.
fn info_offset(bits: BitSize) -> usize {
    match bits {
        BitSize::Bits32 => 12,
        BitSize::Bits64 => 4,
    }
}

#[test]
fn global_function_is_0x12_in_every_layout() {
    for (endian, bits) in LAYOUTS {
        let mut buf = Vec::new();
        entry(StInfoType::STT_FUNC, StInfoBinding::STB_GLOBAL)
            .serialize(&mut buf, endian, bits)
            .unwrap();
        assert_eq!(
            buf[info_offset(bits)],
            0x12,
            "FUNC|GLOBAL must be 0x12 for {endian:?}/{bits:?}"
        );
    }
}

#[test]
fn every_type_and_binding_pair_round_trips_in_every_layout() {
    let types = [
        StInfoType::STT_NOTYPE,
        StInfoType::STT_OBJECT,
        StInfoType::STT_FUNC,
        StInfoType::STT_SECTION,
    ];
    let binds = [
        StInfoBinding::STB_LOCAL,
        StInfoBinding::STB_GLOBAL,
        StInfoBinding::STB_WEAK,
    ];
    for (endian, bits) in LAYOUTS {
        for &t in &types {
            for &b in &binds {
                let original = entry(t, b);
                let mut buf = Vec::new();
                original.serialize(&mut buf, endian, bits).unwrap();
                let back = SymbolEntry::parse(&buf, 0, endian, bits).unwrap();
                assert_eq!(back.st_info_type, t, "{endian:?}/{bits:?}");
                assert_eq!(back.st_info_binding, b, "{endian:?}/{bits:?}");
                assert_eq!(back.st_value, original.st_value);
                assert_eq!(back.st_shndx, original.st_shndx);
            }
        }
    }
}

#[test]
fn a_section_symbol_from_a_real_big_endian_elf_survives_unchanged() {
    // Bytes copied from a real big-endian MIPS vmlinux symbol table:
    // name=0, value=0x80100000, size=0, info=0x03 (LOCAL|SECTION), other=0, shndx=1.
    let raw: [u8; 16] = [0, 0, 0, 0, 0x80, 0x10, 0, 0, 0, 0, 0, 0, 0x03, 0, 0, 1];
    let parsed = SymbolEntry::parse(&raw, 0, Endianness::Big, BitSize::Bits32).unwrap();
    assert_eq!(parsed.st_info_type, StInfoType::STT_SECTION);
    assert_eq!(parsed.st_info_binding, StInfoBinding::STB_LOCAL);
    let mut out = Vec::new();
    parsed
        .serialize(&mut out, Endianness::Big, BitSize::Bits32)
        .unwrap();
    assert_eq!(out, raw, "re-serializing must reproduce the original bytes");
}

#[test]
fn truncated_entries_are_errors_not_panics() {
    for (endian, bits) in LAYOUTS {
        let need = SymbolEntry::entry_size(bits);
        for len in 0..need {
            assert!(SymbolEntry::parse(&vec![0u8; len], 0, endian, bits).is_err());
        }
    }
}
