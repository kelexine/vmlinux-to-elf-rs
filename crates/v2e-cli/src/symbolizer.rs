// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `ElfSymbolizer` glue.

#![forbid(unsafe_code)]

use crate::SectionKind;
use v2e_elf::{
    BitSize, EType, ElfFile, ElfSection, ElfStrtab, Endianness, RelocationEntry, SectionLocator,
    ShType, StInfoBinding, StInfoType, SymbolEntry,
};
use v2e_kallsyms::{KallsymsFinder, KallsymsSymbolType};

/// `SHN_ABS` value (well-known reserved section index).
pub const SHN_ABS: u16 = 0xFFF1;

/// Possible entry-point symbol names, in priority order.
pub const POSSIBLE_ENTRY_POINT_SYMBOLS: &[&str] = &[
    "kernel_entry",
    "microblaze_start",
    "parisc_kernel_start",
    "phys_startup_32",
    "phys_startup_64",
    "phys_start",
    "_stext_lma",
    "res_service",
    "_c_int00",
    "startup_32",
    "startup_64",
    "startup_continue",
    "startup",
    "__start",
    "_start",
    "start_kernel",
    "stext",
    "_stext",
    "_text",
];

/// Build an `ElfFile` from the input bytes and the kallsyms finder.
///
/// # Errors
/// Returns an error string on any failure.
pub fn build_elf(
    file_contents: &[u8],
    finder: &KallsymsFinder,
    elf_machine_override: Option<u32>,
    bit_size_override: Option<u32>,
    base_address_override: Option<u64>,
    bss_size_mb: u32,
) -> Result<ElfFile, String> {
    let endian = if finder.is_big_endian {
        Endianness::Big
    } else {
        Endianness::Little
    };
    let bits = if finder.is_64_bits {
        BitSize::Bits64
    } else {
        BitSize::Bits32
    };

    let has_rela = !finder.elf64_rela.is_empty();

    let mut kernel = if file_contents.starts_with(b"\x7fELF") {
        ElfFile::from_bytes(file_contents).map_err(|e| format!("ELF parse: {e}"))?
    } else {
        let mut k = ElfFile::new(endian, bits);
        let em = elf_machine_override
            .map(|v| v as u16)
            .unwrap_or(finder.elf_machine);
        k.file_header.e_machine = em;
        k.file_header.e_type = EType::ET_EXEC;

        // [0] NULL section.
        let null = ElfSection::new(crate::section_kind_for(ShType::SHT_NULL), "", endian, bits);

        // [1] .kernel progbits.
        let mut progbits = ElfSection::new(
            crate::section_kind_for(ShType::SHT_PROGBITS),
            ".kernel",
            endian,
            bits,
        );
        progbits.header.sh_flags = v2e_elf::sh_flags::SHF_ALLOC
            | v2e_elf::sh_flags::SHF_EXECINSTR
            | v2e_elf::sh_flags::SHF_WRITE;
        let base = base_address_override
            .or(finder.kernel_text_candidate)
            .unwrap_or(0);
        progbits.header.sh_addr = base;

        if has_rela {
            // Punch a hole: .kernel ends at the RELA table start.
            let split = finder.elf64_rela_start;
            progbits.header.sh_size = split as u64;
            progbits.section_contents = file_contents[..split].to_vec();

            k.sections.push(null);
            k.sections.push(progbits);

            // [2] .kernel2 progbits — bytes after the RELA table.
            let mut progbits2 = ElfSection::new(
                crate::section_kind_for(ShType::SHT_PROGBITS),
                ".kernel2",
                endian,
                bits,
            );
            progbits2.header.sh_flags = v2e_elf::sh_flags::SHF_ALLOC
                | v2e_elf::sh_flags::SHF_EXECINSTR
                | v2e_elf::sh_flags::SHF_WRITE;
            progbits2.header.sh_addr = base + finder.elf64_rela_end_excl as u64;
            let end_excl = finder.elf64_rela_end_excl;
            progbits2.header.sh_size = (file_contents.len() - end_excl) as u64;
            progbits2.section_contents = file_contents[end_excl..].to_vec();
            k.sections.push(progbits2);
        } else {
            progbits.section_contents = file_contents.to_vec();
            progbits.header.sh_size = file_contents.len() as u64;
            k.sections.push(null);
            k.sections.push(progbits);
        }

        // .bss
        let mut bss = ElfSection::new(
            crate::section_kind_for(ShType::SHT_NOBITS),
            ".bss",
            endian,
            bits,
        );
        bss.header.sh_flags = v2e_elf::sh_flags::SHF_ALLOC
            | v2e_elf::sh_flags::SHF_EXECINSTR
            | v2e_elf::sh_flags::SHF_WRITE;
        bss.header.sh_size = (bss_size_mb as u64) * 1024 * 1024;
        bss.header.sh_addr = base + file_contents.len() as u64;
        k.sections.push(bss);

        k
    };

    // Find the entry-point symbol.
    let mut entry_point_address: Option<u64> = None;
    for name in POSSIBLE_ENTRY_POINT_SYMBOLS {
        if let Some(sym) = finder.name_to_symbol.get(*name) {
            entry_point_address = Some(sym.virtual_address);
            break;
        }
    }
    let entry = entry_point_address
        .ok_or_else(|| "No entry point symbol found in the kallsyms".to_string())?;
    kernel.file_header.e_entry = entry;

    // Add a fresh .symtab + .strtab + .shstrtab if not already present.
    let has_symtab = kernel.sections.iter().any(|s| s.section_name == ".symtab");
    if !has_symtab {
        let mut symtab = ElfSection::new(
            crate::section_kind_for(ShType::SHT_SYMTAB),
            ".symtab",
            endian,
            bits,
        );
        let mut strtab_section = ElfSection::new(
            crate::section_kind_for(ShType::SHT_STRTAB),
            ".strtab",
            endian,
            bits,
        );
        strtab_section.strtab = Some(ElfStrtab::new());
        let mut shstrtab = ElfSection::new(
            crate::section_kind_for(ShType::SHT_STRTAB),
            ".shstrtab",
            endian,
            bits,
        );
        shstrtab.strtab = Some(ElfStrtab::new());

        // Populate symbols. At this point kernel.sections = [NULL, .kernel,
        // (.kernel2 if RELA), .bss]. The section indices are stable because
        // we push symtab/strtab/shstrtab/.rela.dyn AFTER this loop.
        let locator = kernel.section_locator();
        symtab.symbols = kallsyms_to_symbols(finder, &locator);

        // Attach strtab to symtab and populate st_name offsets.
        let mut strtab_clone = strtab_section.strtab.clone().unwrap();
        symtab.strtab = Some(strtab_clone.clone());
        for sym in &mut symtab.symbols {
            let off = strtab_clone.add_string(&sym.symbol_name);
            sym.st_name = off;
        }
        strtab_section.section_contents = strtab_clone.raw.clone();

        // Sort symbols: LOCAL first.
        symtab.symbols.sort_by_key(|s| match s.st_info_binding {
            StInfoBinding::STB_LOCAL => 0,
            _ => 1,
        });
        let first_non_local = symtab
            .symbols
            .iter()
            .position(|s| s.st_info_binding != StInfoBinding::STB_LOCAL);
        symtab.header.sh_info = first_non_local.unwrap_or(symtab.symbols.len()) as u32;

        // Serialize symtab section_contents.
        let mut symtab_bytes: Vec<u8> =
            Vec::with_capacity(symtab.symbols.len() * SymbolEntry::entry_size(bits));
        for s in &symtab.symbols {
            s.serialize(&mut symtab_bytes, endian, bits)
                .map_err(|e| format!("symtab serialize: {e}"))?;
        }
        symtab.section_contents = symtab_bytes;
        if symtab.header.sh_entsize == 0 {
            symtab.header.sh_entsize = SymbolEntry::entry_size(bits) as u64;
        }

        // Build .rela.dyn section (if RELA was found).
        let mut rela_section_opt: Option<ElfSection> = if has_rela {
            Some(build_rela_section(finder, endian, bits)?)
        } else {
            None
        };

        // Build shstrtab from ALL section names (including .rela.dyn if present).
        let mut shstrtab_inner = ElfStrtab::new();
        for s in &kernel.sections {
            let _ = shstrtab_inner.add_string(&s.section_name);
        }
        let _ = shstrtab_inner.add_string(&symtab.section_name);
        let _ = shstrtab_inner.add_string(&strtab_section.section_name);
        let _ = shstrtab_inner.add_string(&shstrtab.section_name);
        if let Some(ref rs) = rela_section_opt {
            let _ = shstrtab_inner.add_string(&rs.section_name);
        }
        shstrtab.section_contents = shstrtab_inner.raw.clone();
        shstrtab.strtab = Some(shstrtab_inner);

        // Update sh_name for all sections via shstrtab.
        let mut shstrtab_clone = shstrtab.strtab.clone().unwrap();
        for s in &mut kernel.sections {
            s.header.sh_name = shstrtab_clone.add_string(&s.section_name);
        }
        symtab.header.sh_name = shstrtab_clone.add_string(&symtab.section_name);
        strtab_section.header.sh_name = shstrtab_clone.add_string(&strtab_section.section_name);
        shstrtab.header.sh_name = shstrtab_clone.add_string(&shstrtab.section_name);
        if let Some(ref mut rs) = rela_section_opt {
            rs.header.sh_name = shstrtab_clone.add_string(&rs.section_name);
        }

        // Push sections in order: .symtab, .strtab, .shstrtab, (.rela.dyn).
        kernel.sections.push(symtab);
        kernel.sections.push(strtab_section);
        kernel.sections.push(shstrtab);

        let symtab_idx = kernel.sections.len() - 3;
        let strtab_idx = kernel.sections.len() - 2;
        let shstrtab_idx = kernel.sections.len() - 1;
        kernel.sections[symtab_idx].header.sh_link = strtab_idx as u32;
        kernel.section_string_table_index = Some(shstrtab_idx);
        kernel.symbol_table_index = Some(symtab_idx);

        // Push .rela.dyn last and set its sh_link to symtab.
        if let Some(mut rs) = rela_section_opt {
            rs.header.sh_link = symtab_idx as u32;
            kernel.sections.push(rs);
        }
    } else {
        append_to_existing_symtab(&mut kernel, finder, endian, bits, has_rela)?;
    }

    let _ = (elf_machine_override, bit_size_override);
    Ok(kernel)
}

/// Convert the finder's kallsyms symbols into ELF symbol entries.
///
/// Each symbol is attached to the section that contains its address (a symbol
/// exactly on a boundary belongs to the section that starts there); absolute symbols get `SHN_ABS`.
fn kallsyms_to_symbols(finder: &KallsymsFinder, locator: &SectionLocator) -> Vec<SymbolEntry> {
    finder
        .symbols
        .iter()
        .map(|s| {
            let mut sym = SymbolEntry::default();
            sym.symbol_name = s.name.clone();
            sym.st_value = s.virtual_address;
            sym.st_info_type = if matches!(
                s.symbol_type,
                Some(KallsymsSymbolType::Text) | Some(KallsymsSymbolType::WeakSymbolWithDefault)
            ) {
                StInfoType::STT_FUNC
            } else {
                StInfoType::STT_OBJECT
            };
            sym.st_info_binding = if matches!(
                s.symbol_type,
                Some(KallsymsSymbolType::WeakObjectWithDefault)
                    | Some(KallsymsSymbolType::WeakSymbolWithDefault)
            ) {
                StInfoBinding::STB_WEAK
            } else if s.is_global {
                StInfoBinding::STB_GLOBAL
            } else {
                StInfoBinding::STB_LOCAL
            };
            if matches!(s.symbol_type, Some(KallsymsSymbolType::Absolute)) {
                sym.st_shndx = SHN_ABS;
            } else if let Some(i) = locator.find(s.virtual_address) {
                sym.st_shndx = u16::try_from(i).unwrap_or(0);
            }
            sym
        })
        .collect()
}

/// Build the `.rela.dyn` section from the relocations the finder discovered.
fn build_rela_section(
    finder: &KallsymsFinder,
    endian: Endianness,
    bits: BitSize,
) -> Result<ElfSection, String> {
    let mut rela_section = ElfSection::new(
        crate::section_kind_for(ShType::SHT_RELA),
        ".rela.dyn",
        endian,
        bits,
    );
    for rela in &finder.elf64_rela {
        rela_section.relocations.push(RelocationEntry {
            r_offset: rela.r_offset,
            r_info: rela.r_info & 0xFFFF_FFFF,
            r_addend: Some(rela.r_addend),
        });
    }
    let mut rela_bytes: Vec<u8> = Vec::with_capacity(
        rela_section.relocations.len() * RelocationEntry::entry_size(bits, true),
    );
    for r in &rela_section.relocations {
        r.serialize(&mut rela_bytes, endian, bits)
            .map_err(|e| format!("rela serialize: {e}"))?;
    }
    rela_section.section_contents = rela_bytes;
    if rela_section.header.sh_entsize == 0 {
        rela_section.header.sh_entsize = RelocationEntry::entry_size(bits, true) as u64;
    }
    Ok(rela_section)
}

/// The input ELF already has a `.symtab`: reuse it and append the kallsyms
/// symbols, exactly like the reference tool does.
///
/// Steps:
/// 1. rebuild the linked string table's cache by walking its strings
///    (last duplicate wins),
/// 2. append the kallsyms symbols after the existing ones,
/// 3. re-resolve every symbol's `st_name` through the string table (names the
///    table cannot find, e.g. tail-merged suffixes, are appended),
/// 4. stably sort locals first and set `sh_info` to the first non-local,
/// 5. refresh `sh_entsize` and the symtab/strtab section contents.
fn append_to_existing_symtab(
    kernel: &mut ElfFile,
    finder: &KallsymsFinder,
    endian: Endianness,
    bits: BitSize,
    has_rela: bool,
) -> Result<(), String> {
    let symtab_idx = kernel
        .sections
        .iter()
        .position(|s| s.section_name == ".symtab")
        .ok_or_else(|| "internal error: .symtab disappeared".to_string())?;

    let strtab_idx = usize::try_from(kernel.sections[symtab_idx].header.sh_link)
        .map_err(|_| "symtab sh_link does not fit usize".to_string())?;
    let strtab_ok = kernel.sections.get(strtab_idx).is_some_and(|s| {
        matches!(
            crate::section_kind_for(s.header.sh_type),
            SectionKind::Strtab
        )
    });
    if !strtab_ok {
        return Err(format!(
            "the input ELF's .symtab links to section {strtab_idx}, which is not a string table"
        ));
    }

    let mut strtab = ElfStrtab::new();
    strtab.set_raw(kernel.sections[strtab_idx].section_contents.clone());

    let locator = kernel.section_locator();
    let new_symbols = kallsyms_to_symbols(finder, &locator);

    let symtab = &mut kernel.sections[symtab_idx];
    symtab.symbols.extend(new_symbols);
    for sym in &mut symtab.symbols {
        sym.st_name = strtab.add_string(&sym.symbol_name);
    }

    // `sort_by_key` is stable, like Python's `sorted`.
    symtab
        .symbols
        .sort_by_key(|s| s.st_info_binding != StInfoBinding::STB_LOCAL);
    if let Some(first_non_local) = symtab
        .symbols
        .iter()
        .position(|s| s.st_info_binding != StInfoBinding::STB_LOCAL)
    {
        symtab.header.sh_info =
            u32::try_from(first_non_local).map_err(|_| "too many symbols".to_string())?;
    }

    let entry_size = SymbolEntry::entry_size(bits);
    let mut bytes: Vec<u8> = Vec::with_capacity(symtab.symbols.len() * entry_size);
    for s in &symtab.symbols {
        s.serialize(&mut bytes, endian, bits)
            .map_err(|e| format!("symtab serialize: {e}"))?;
    }
    symtab.section_contents = bytes;
    symtab.header.sh_entsize = entry_size as u64;

    let strtab_section = &mut kernel.sections[strtab_idx];
    strtab_section.section_contents = strtab.raw.clone();
    strtab_section.strtab = Some(strtab);

    kernel.symbol_table_index = Some(symtab_idx);

    if has_rela {
        let mut rela = build_rela_section(finder, endian, bits)?;
        rela.header.sh_link =
            u32::try_from(symtab_idx).map_err(|_| "too many sections".to_string())?;
        kernel.sections.push(rela);
    }
    Ok(())
}
