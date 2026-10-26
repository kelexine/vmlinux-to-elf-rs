// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `KallsymsFinder` orchestrator.

#![forbid(unsafe_code)]

use crate::detect::{
    addresses::find_addresses_or_offsets, markers::find_kallsyms_markers,
    names::find_kallsyms_names, num_syms::find_kallsyms_num_syms,
    token_index::find_kallsyms_token_index, token_table::find_kallsyms_token_table,
};
use crate::error::KallsymsError;
use crate::rela::{Elf64Rela, RELA64_SIZE, R_AARCH64_ABS64, R_AARCH64_RELATIVE};
use crate::symbol::{KallsymsSymbol, KallsymsSymbolType};
use crate::version::{find_linux_kernel_version, KernelVersionInfo};
use v2e_arch::{ArchitectureDetector, ArchitectureName};

/// Configuration for `KallsymsFinder`.
#[derive(Clone, Debug, Default)]
pub struct KallsymsFinderConfig {
    /// Force the bit size (32 or 64) instead of auto-detection.
    pub bit_size: Option<u32>,
    /// `--use-absolute` — assume offsets are absolute addresses.
    pub override_relative_base: bool,
    /// `--base-address` — force the output ELF base address.
    pub explicit_base_address: Option<u64>,
}

/// Main structure that holds kallsyms data.
pub struct KallsymsFinder {
    /// Raw kernel image bytes (post-relocation if applicable).
    pub kernel_img: Vec<u8>,
    /// Decoded version info.
    pub version: KernelVersionInfo,
    /// Inferred architecture.
    pub architecture: Option<ArchitectureName>,
    /// ELF `e_machine` value to use.
    pub elf_machine: u16,
    /// Whether the kernel is 64-bit.
    pub is_64_bits: bool,
    /// Endianness.
    pub is_big_endian: bool,
    /// Decoded symbol table.
    pub symbols: Vec<KallsymsSymbol>,
    /// Name → symbol lookup.
    pub name_to_symbol: std::collections::HashMap<String, KallsymsSymbol>,
    /// Whether RELA processing was applied (ARM64).
    pub is_relocated: bool,
    /// Detected kallsyms_token_table offset.
    pub kallsyms_token_table_offset: usize,
    /// Detected kallsyms_token_index offset.
    pub kallsyms_token_index_offset: usize,
    /// Detected kallsyms_token_index end offset.
    pub kallsyms_token_index_end_offset: usize,
    /// Detected kallsyms_markers offset.
    pub kallsyms_markers_offset: usize,
    /// Detected kallsyms_names offset.
    pub kallsyms_names_offset: usize,
    /// Detected kallsyms_num_syms offset.
    pub kallsyms_num_syms_offset: usize,
    /// Detected kallsyms_addresses_or_offsets offset.
    pub kallsyms_addresses_offset: usize,
    /// Inferred kernel base address.
    pub kernel_text_candidate: Option<u64>,
    /// Decoded RELA entries (ARM64 only).
    pub elf64_rela: Vec<Elf64Rela>,
    /// File offset where the RELA table begins (0 if no RELA).
    pub elf64_rela_start: usize,
    /// File offset one past the end of the RELA table (0 if no RELA).
    pub elf64_rela_end_excl: usize,
    /// Offset table element size (2/4/8).
    pub offset_table_element_size: usize,
    /// Decoded kernel addresses.
    pub kernel_addresses: Vec<u64>,
    /// Whether `CONFIG_KALLSYMS_BASE_RELATIVE` was inferred.
    pub has_base_relative: bool,
    /// Whether `CONFIG_KALLSYMS_ABSOLUTE_PERCPU` was inferred.
    pub has_absolute_percpu: bool,
    /// Decoded relative base address.
    pub relative_base_address: Option<u64>,
}

impl KallsymsFinder {
    /// Construct by running the full 13-step pipeline.
    ///
    /// # Errors
    /// Returns [`KallsymsError`] on any failure.
    pub fn new(kernel_img: Vec<u8>, cfg: KallsymsFinderConfig) -> Result<Self, KallsymsError> {
        let mut kernel_img = kernel_img;
        let mut is_64_bits = match cfg.bit_size {
            Some(64) => true,
            Some(32) => false,
            Some(_) => return Err(KallsymsError::ArchitectureGuess),
            None => false,
        };

        // Step 1: find Linux kernel version.
        let version = find_linux_kernel_version(&kernel_img)?;

        // Step 2: guess architecture.
        let mut architecture: Option<ArchitectureName> = None;
        let mut elf_machine: u16 = 0;
        let mut is_big_endian = false;
        match ArchitectureDetector::guess(&kernel_img) {
            Ok(res) => {
                architecture = Some(res.architecture_name);
                elf_machine = res.elf_machine;
                if cfg.bit_size.is_none() {
                    is_64_bits = res.is_64_bit;
                }
                is_big_endian = res.is_big_endian;
            },
            Err(_) => {
                if cfg.bit_size.is_none() {
                    return Err(KallsymsError::ArchitectureGuess);
                }
            },
        }
        log::info!(
            "[+] Guessed architecture: {}",
            architecture
                .map(|a| a.readable_name())
                .unwrap_or("(unknown)")
        );

        // Step 3: find kallsyms_token_table.
        let token_table = find_kallsyms_token_table(&kernel_img)?;
        let tt_offset = token_table.offset;

        // Step 4: find kallsyms_token_index. This sets is_big_endian!
        let token_index = find_kallsyms_token_index(&kernel_img, tt_offset)?;
        is_big_endian = token_index.is_big_endian;

        // Step 5: find kallsyms_markers.
        let markers = find_kallsyms_markers(&kernel_img, tt_offset, is_big_endian)?;
        let offset_table_element_size = markers.offset_table_element_size;

        // Step 6: find kallsyms_names (approximate).
        let names = find_kallsyms_names(&kernel_img, &markers, tt_offset, is_big_endian)?;
        let mut names_offset = names.offset;

        // Build the token table for symbol-name decode.
        let tokens = build_token_table(&kernel_img, tt_offset);

        // Step 7: find kallsyms_num_syms (uses tokens for the first-symbol-type check).
        let (num_syms, names_offset_final) = find_kallsyms_num_syms(
            &kernel_img,
            names_offset,
            markers.offset,
            &tokens,
            is_big_endian,
            offset_table_element_size,
        )?;
        names_offset = names_offset_final;
        let num_symbols = num_syms.num_symbols;
        let num_syms_offset = num_syms.offset;

        // Step 8: ARM64 RELA scan + apply (only for 64-bit aarch64).
        let mut is_relocated = false;
        let mut elf64_rela: Vec<Elf64Rela> = Vec::new();
        let mut elf64_rela_start: usize = 0;
        let mut elf64_rela_end_excl: usize = 0;
        let mut kernel_text_candidate: Option<u64> = cfg.explicit_base_address;
        if is_64_bits && architecture == Some(ArchitectureName::aarch64) {
            if let Some((rela, ktc, rstart, rend)) =
                find_elf64_rela(&kernel_img, cfg.explicit_base_address)
            {
                elf64_rela = rela;
                elf64_rela_start = rstart;
                elf64_rela_end_excl = rend;
                kernel_text_candidate = ktc.or(kernel_text_candidate);
                apply_elf64_rela(
                    &mut kernel_img,
                    &elf64_rela,
                    kernel_text_candidate,
                    num_syms_offset,
                    token_index.end_offset,
                );
                is_relocated = true;
            }
        }

        // Step 9: find kallsyms_addresses_or_offsets.
        let addrs = find_addresses_or_offsets(
            &kernel_img,
            is_64_bits,
            is_big_endian,
            num_symbols,
            offset_table_element_size,
            token_index.end_offset,
            num_syms_offset,
            version.major,
            version.minor,
            &version.version_string,
            cfg.override_relative_base,
            cfg.explicit_base_address,
        )?;

        // Step 10: parse the symbol table (decode names + addresses).
        let symbols = parse_symbol_table(
            &kernel_img,
            names_offset,
            num_symbols,
            &tokens,
            &addrs.kernel_addresses,
        );

        let mut name_to_symbol: std::collections::HashMap<String, KallsymsSymbol> =
            std::collections::HashMap::with_capacity(symbols.len());
        for s in &symbols {
            name_to_symbol.insert(s.name.clone(), s.clone());
        }

        // Step 11: infer base address if not set.
        if kernel_text_candidate.is_none() {
            kernel_text_candidate = infer_base_address_from_syms(
                &symbols,
                addrs.relative_base_address,
                addrs.has_base_relative,
            );
        }

        Ok(Self {
            kernel_img,
            version,
            architecture,
            elf_machine,
            is_64_bits,
            is_big_endian,
            symbols,
            name_to_symbol,
            is_relocated,
            kallsyms_token_table_offset: tt_offset,
            kallsyms_token_index_offset: token_index.offset,
            kallsyms_token_index_end_offset: token_index.end_offset,
            kallsyms_markers_offset: markers.offset,
            kallsyms_names_offset: names_offset,
            kallsyms_num_syms_offset: num_syms_offset,
            kallsyms_addresses_offset: addrs.offset,
            kernel_text_candidate,
            elf64_rela,
            elf64_rela_start,
            elf64_rela_end_excl,
            offset_table_element_size,
            kernel_addresses: addrs.kernel_addresses,
            has_base_relative: addrs.has_base_relative,
            has_absolute_percpu: addrs.has_absolute_percpu,
            relative_base_address: addrs.relative_base_address,
        })
    }

    /// Print all symbols in `/proc/kallsyms`-style to `out`.
    pub fn print_symbols_debug<W: std::io::Write>(&self, out: &mut W) -> std::io::Result<()> {
        for (addr, sym) in self.kernel_addresses.iter().zip(self.symbols.iter()) {
            let type_letter = sym.type_letter;
            if self.is_64_bits {
                writeln!(out, "{:016x} {} {}", addr, type_letter, sym.name)?;
            } else {
                writeln!(out, "{:08x} {} {}", addr, type_letter, sym.name)?;
            }
        }
        Ok(())
    }
}

fn build_token_table(kernel_img: &[u8], tt_offset: usize) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::with_capacity(256);
    let mut pos = tt_offset;
    for _ in 0..256 {
        let mut s = String::new();
        while pos < kernel_img.len() && kernel_img[pos] != 0 {
            s.push(kernel_img[pos] as char);
            pos += 1;
        }
        pos += 1; // skip NUL
        tokens.push(s);
    }
    tokens
}

fn parse_symbol_table(
    kernel_img: &[u8],
    names_offset: usize,
    num_symbols: usize,
    tokens: &[String],
    addresses: &[u64],
) -> Vec<KallsymsSymbol> {
    let mut symbols: Vec<KallsymsSymbol> = Vec::with_capacity(num_symbols);
    let mut pos = names_offset;
    for i in 0..num_symbols {
        if pos >= kernel_img.len() {
            break;
        }
        let mut length = kernel_img[pos] as usize;
        pos += 1;
        if length & 0x80 != 0 {
            if pos >= kernel_img.len() {
                break;
            }
            length = (length & 0x7F) | ((kernel_img[pos] as usize) << 7);
            pos += 1;
        }
        let mut symbol_name = String::new();
        for _ in 0..length {
            if pos >= kernel_img.len() {
                break;
            }
            let idx = kernel_img[pos] as usize;
            if idx < tokens.len() {
                symbol_name.push_str(&tokens[idx]);
            }
            pos += 1;
        }

        // Build symbol object.
        let addr = addresses.get(i).copied().unwrap_or(0);
        let (symbol_type, is_global, type_letter) = if !symbol_name.is_empty() {
            let first = symbol_name.as_bytes()[0] as char;
            let first_lower = first.to_ascii_lowercase();
            if matches!(first_lower, 'u' | 'v' | 'w') {
                // u/v/w are weak symbols; is_global=True regardless of case.
                (KallsymsSymbolType::from_letter(first), true, first)
            } else {
                (
                    KallsymsSymbolType::from_letter(first.to_ascii_uppercase()),
                    first.is_ascii_uppercase(),
                    first,
                )
            }
        } else {
            (None, false, '?')
        };
        let name = if !symbol_name.is_empty() {
            symbol_name[1..].to_string()
        } else {
            String::new()
        };
        symbols.push(KallsymsSymbol {
            name,
            file_offset: None,
            virtual_address: addr,
            symbol_type,
            type_letter,
            is_global,
        });
    }
    symbols
}

fn infer_base_address_from_syms(
    symbols: &[KallsymsSymbol],
    relative_base: Option<u64>,
    has_base_relative: bool,
) -> Option<u64> {
    let first_text = symbols
        .iter()
        .find(|s| matches!(s.symbol_type, Some(KallsymsSymbolType::Text)))
        .map(|s| s.virtual_address);
    let first_text = first_text?;
    if has_base_relative {
        if let Some(base) = relative_base {
            if base < first_text {
                let aligned = base & 0xFFFF_FFFF_FFFF_E000;
                log::info!(
                    "[+] Guessed the base address using the kallsyms_relative_base value ({:#x} aligned to {:#x})",
                    base,
                    aligned
                );
                return Some(aligned);
            }
        }
    }
    let aligned = first_text & 0xFFFF_FFFF_FFFF_E000;
    log::info!(
        "[+] Guessed the base address using the first_symbol_virtual_address fallback heuristic ({:#x})",
        aligned
    );
    Some(aligned)
}

/// ARM64 RELA scan. Returns `(entries, kernel_text_candidate, rela_start_offset, rela_end_excl_offset)`.
fn find_elf64_rela(
    kernel_img: &[u8],
    explicit_base: Option<u64>,
) -> Option<(Vec<Elf64Rela>, Option<u64>, usize, usize)> {
    let max_rela_offset = kernel_img.len().saturating_sub(RELA64_SIZE);
    if max_rela_offset < 1 {
        return None;
    }
    let supported_types = [R_AARCH64_ABS64, R_AARCH64_RELATIVE];
    let minimal_heuristic_count = 1000usize;
    let minimal_kernel_va = 0xFFFF_C000_8000_0000u64;

    let mut best_start: usize = 0;
    let mut best_end: usize = 0;
    let mut best_count: usize = 0;
    let mut position: usize = 0;

    while position <= max_rela_offset {
        let r_offset = u64::from_le_bytes([
            kernel_img[position],
            kernel_img[position + 1],
            kernel_img[position + 2],
            kernel_img[position + 3],
            kernel_img[position + 4],
            kernel_img[position + 5],
            kernel_img[position + 6],
            kernel_img[position + 7],
        ]);
        let r_info = u64::from_le_bytes([
            kernel_img[position + 8],
            kernel_img[position + 9],
            kernel_img[position + 10],
            kernel_img[position + 11],
            kernel_img[position + 12],
            kernel_img[position + 13],
            kernel_img[position + 14],
            kernel_img[position + 15],
        ]);
        let r_addend = i64::from_le_bytes([
            kernel_img[position + 16],
            kernel_img[position + 17],
            kernel_img[position + 18],
            kernel_img[position + 19],
            kernel_img[position + 20],
            kernel_img[position + 21],
            kernel_img[position + 22],
            kernel_img[position + 23],
        ]);
        let r_type = (r_info & 0xFFFF_FFFF) as u32;
        let is_supported = supported_types.contains(&r_type)
            && (r_offset & 0xFFFF_0000_0000_0000) == 0xFFFF_0000_0000_0000;
        if !is_supported {
            position += 8;
            continue;
        }
        let run_start = position;
        let mut cursor = position;
        let mut last_nonempty_end = position;
        while cursor <= max_rela_offset {
            let off = cursor;
            let r = read_rela(kernel_img, off);
            if r.is_none() {
                break;
            }
            let (r_offset, r_info, r_addend) = r.unwrap();
            if r_offset == 0 && r_info == 0 && r_addend == 0 {
                cursor += RELA64_SIZE;
                continue;
            }
            let r_type = (r_info & 0xFFFF_FFFF) as u32;
            let supported = supported_types.contains(&r_type)
                && (r_offset & 0xFFFF_0000_0000_0000) == 0xFFFF_0000_0000_0000;
            if !supported {
                break;
            }
            cursor += RELA64_SIZE;
            last_nonempty_end = cursor;
        }
        let run_count = (last_nonempty_end - run_start) / RELA64_SIZE;
        if run_count > best_count {
            best_count = run_count;
            best_start = run_start;
            best_end = last_nonempty_end;
        }
        if run_count < minimal_heuristic_count {
            position = run_start + 8;
        } else {
            position = cursor;
        }
    }
    if best_count < minimal_heuristic_count {
        return None;
    }

    // Collect entries.
    let mut entries: Vec<Elf64Rela> = Vec::with_capacity(best_count);
    let mut addend_candidate: Option<u64> = None;
    let mut has_abs64 = false;
    for p in (best_start..best_end).step_by(RELA64_SIZE) {
        if let Some((ro, ri, ra)) = read_rela(kernel_img, p) {
            if ro == 0 && ri == 0 && ra == 0 {
                continue;
            }
            entries.push(Elf64Rela {
                r_offset: ro,
                r_info: ri,
                r_addend: ra,
            });
            let r_type = (ri & 0xFFFF_FFFF) as u32;
            if r_type == R_AARCH64_ABS64 {
                has_abs64 = true;
            } else if r_type == R_AARCH64_RELATIVE
                && (ra & 0xFFF) == 0
                && (ra as u64) >= minimal_kernel_va
            {
                if addend_candidate.is_none() || (ra as u64) < addend_candidate.unwrap() {
                    addend_candidate = Some(ra as u64);
                }
            }
        }
    }

    log::info!(
        "[+] Found relocations table at file offset 0x{:04x} - 0x{:04x} (count={})",
        best_start,
        best_end,
        best_count
    );

    // `find_elf64_rela` kernel-text-candidate inference:
    //   - explicit_base (always wins)
    //   - else: derive from relocation-offset range, aligned up to 0x80000
    //   - else: use addend_candidate if it fits
    //   - else: use addend_candidate anyway
    let img_len = kernel_img.len() as u64;

    let mut min_offset = u64::MAX;
    let mut max_offset = 0u64;
    for r in &entries {
        if r.r_offset < min_offset {
            min_offset = r.r_offset;
        }
        if r.r_offset > max_offset {
            max_offset = r.r_offset;
        }
    }
    let base_low = max_offset.saturating_sub(img_len.saturating_sub(8));
    let base_high = min_offset;

    let fits =
        |base: Option<u64>| -> bool { base.is_some_and(|b| base_low <= b && b <= base_high) };

    let ktc: Option<u64> = if let Some(explicit) = explicit_base {
        Some(explicit)
    } else if base_low <= base_high
        && (has_abs64 || addend_candidate.is_none() || !fits(addend_candidate))
    {
        // Derive from offset range.
        const ALIGN: u64 = 0x80000;
        let mut candidate = (base_low + ALIGN - 1) & !(ALIGN - 1);
        if candidate > base_high {
            candidate = base_high & !(ALIGN - 1);
        }
        Some(candidate)
    } else {
        addend_candidate
    };
    Some((entries, ktc, best_start, best_end))
}

fn read_rela(data: &[u8], off: usize) -> Option<(u64, u64, i64)> {
    if off + RELA64_SIZE > data.len() {
        return None;
    }
    let r_offset = u64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ]);
    let r_info = u64::from_le_bytes([
        data[off + 8],
        data[off + 9],
        data[off + 10],
        data[off + 11],
        data[off + 12],
        data[off + 13],
        data[off + 14],
        data[off + 15],
    ]);
    let r_addend = i64::from_le_bytes([
        data[off + 16],
        data[off + 17],
        data[off + 18],
        data[off + 19],
        data[off + 20],
        data[off + 21],
        data[off + 22],
        data[off + 23],
    ]);
    Some((r_offset, r_info, r_addend))
}

/// Apply RELA entries to `kernel_img`.
fn apply_elf64_rela(
    kernel_img: &mut Vec<u8>,
    entries: &[Elf64Rela],
    kernel_text: Option<u64>,
    kallsyms_begin: usize,
    kallsyms_end: usize,
) {
    let Some(kernel_base) = kernel_text else {
        return;
    };
    let offset_max = kernel_img.len().saturating_sub(8);
    let mut count = 0usize;

    for rela in entries {
        let r_type = rela.r_info_type();
        let offset = (rela.r_offset.wrapping_sub(kernel_base)) as usize;
        if offset >= offset_max || (kallsyms_begin <= offset && offset < kallsyms_end) {
            log::warn!("[!] WARNING! bad rela offset {:08x}", rela.r_offset);
            return;
        }
        if offset + 8 > kernel_img.len() {
            return;
        }
        let mut value = u64::from_le_bytes([
            kernel_img[offset],
            kernel_img[offset + 1],
            kernel_img[offset + 2],
            kernel_img[offset + 3],
            kernel_img[offset + 4],
            kernel_img[offset + 5],
            kernel_img[offset + 6],
            kernel_img[offset + 7],
        ]);
        if value == rela.r_addend as u64 {
            continue;
        }
        let mut addend = rela.r_addend as u64;
        if r_type == R_AARCH64_ABS64 {
            addend = addend.wrapping_add(kernel_base);
        }
        value = value.wrapping_add(addend);
        kernel_img[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        count += 1;
    }
    log::info!("[+] Successfully applied {} relocations.", count);
}
