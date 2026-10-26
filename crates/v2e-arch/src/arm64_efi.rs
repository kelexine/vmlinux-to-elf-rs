// SPDX-License-Identifier: GPL-3.0-or-later
//! ARM64 PE/EFI stub parser.
//! UEFI is always little-endian; this struct matches the Linux ARM64 boot header at `arch/arm64/kernel/efi-header.S`.

#![forbid(unsafe_code)]
#![allow(missing_docs)]
#![allow(clippy::struct_excessive_bools)]

/// ARM64 PE/EFI boot stub header.
#[derive(Clone, Debug)]
#[allow(non_snake_case)]
pub struct LinuxArm64EfiStub {
    /// ARM64 code: `MZ@\xFA` (4 bytes).
    pub code0: [u8; 4],
    /// ARM64 code: `b primary_entry`.
    pub code1: u32,
    /// Image load offset, effectively 0.
    pub text_offset: u64,
    /// Effective image size, `_kernel_size_le`, 0x02000000 = 32 MB.
    pub image_size: u64,
    /// `_kernel_flags_le`. Bit 0 = kernel endianness (1=BE, 0=LE).
    pub flags: u64,
    pub res2: u64,
    pub res3: u64,
    pub res4: u64,
    /// Magic `ARM\x64`.
    pub magic: [u8; 4],
    /// Offset to the PE header (0x40).
    pub pe_header_offset: u32,
    /// `PE\0\0`.
    pub pe_magic: [u8; 4],
    /// `IMAGE_FILE_MACHINE_ARM64` = 0xAA64.
    pub pe_machine: u16,
    pub pe_section_count: u16,
    pub pe_date_timestamp: u32,
    pub pe_pointer_to_symbol_table: u32,
    pub pe_number_of_symbols: u32,
    pub pe_size_of_optional_header: u16,
    pub pe_characteristics: u16,
    /// PE32+ magic = 0x020B.
    pub pe32plus_magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub export_table: u64,
    pub import_table: u64,
    pub resource_table: u64,
    pub exception_table: u64,
    pub certification_table: u64,
    pub base_relocation_table: u64,
}

impl LinuxArm64EfiStub {
    /// Magic bytes `ARM\x64` (big-endian 0x41524D64).
    pub const MAGIC: [u8; 4] = [b'A', b'R', b'M', 0x64];

    /// Parse a stub from `data` starting at offset 0. Returns `None` if
    /// the input is too short or the magic bytes are wrong.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 0x100 {
            return None;
        }
        let magic = [data[0x38], data[0x39], data[0x3a], data[0x3b]];
        if magic != Self::MAGIC {
            return None;
        }
        let rd = |off: usize| {
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        };
        let rd16 = |off: usize| u16::from_le_bytes([data[off], data[off + 1]]);
        let rd8 = |off: usize| data[off];
        let rd64 = |off: usize| {
            u64::from_le_bytes([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
                data[off + 4],
                data[off + 5],
                data[off + 6],
                data[off + 7],
            ])
        };
        Some(Self {
            code0: [data[0], data[1], data[2], data[3]],
            code1: rd(4),
            text_offset: rd64(8),
            image_size: rd64(16),
            flags: rd64(24),
            res2: rd64(32),
            res3: rd64(40),
            res4: rd64(48),
            magic,
            pe_header_offset: rd(0x3c),
            pe_magic: [data[0x40], data[0x41], data[0x42], data[0x43]],
            pe_machine: rd16(0x44),
            pe_section_count: rd16(0x46),
            pe_date_timestamp: rd(0x48),
            pe_pointer_to_symbol_table: rd(0x4c),
            pe_number_of_symbols: rd(0x50),
            pe_size_of_optional_header: rd16(0x54),
            pe_characteristics: rd16(0x56),
            pe32plus_magic: rd16(0x58),
            major_linker_version: rd8(0x5a),
            minor_linker_version: rd8(0x5b),
            size_of_code: rd(0x5c),
            size_of_initialized_data: rd(0x60),
            size_of_uninitialized_data: rd(0x64),
            address_of_entry_point: rd(0x68),
            base_of_code: rd(0x6c),
            image_base: rd64(0x70),
            section_alignment: rd(0x78),
            file_alignment: rd(0x7c),
            major_os_version: rd16(0x80),
            minor_os_version: rd16(0x82),
            major_image_version: rd16(0x84),
            minor_image_version: rd16(0x86),
            major_subsystem_version: rd16(0x88),
            minor_subsystem_version: rd16(0x8a),
            win32_version_value: rd(0x8c),
            size_of_image: rd(0x90),
            size_of_headers: rd(0x94),
            checksum: rd(0x98),
            subsystem: rd16(0x9c),
            dll_characteristics: rd16(0x9e),
            size_of_stack_reserve: rd64(0xa0),
            size_of_stack_commit: rd64(0xa8),
            size_of_heap_reserve: rd64(0xb0),
            size_of_heap_commit: rd64(0xb8),
            loader_flags: rd(0xc0),
            number_of_rva_and_sizes: rd(0xc4),
            export_table: rd64(0xc8),
            import_table: rd64(0xd0),
            resource_table: rd64(0xd8),
            exception_table: rd64(0xe0),
            certification_table: rd64(0xe8),
            base_relocation_table: rd64(0xf0),
        })
    }
}

/// One PE/COFF section table entry (`IMAGE_SECTION_HEADER`).
#[derive(Clone, Debug)]
pub struct SectionTableEntry {
    /// 8-byte name (NUL-padded).
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: u32,
}

impl SectionTableEntry {
    /// Parse a section table entry at `offset`. Returns `None` on truncation.
    #[must_use]
    pub fn parse(data: &[u8], offset: usize) -> Option<Self> {
        const SIZE: usize = 40;
        if data.len() < offset + SIZE {
            return None;
        }
        let mut name = [0u8; 8];
        name.copy_from_slice(&data[offset..offset + 8]);
        let rd = |off: usize| {
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        };
        let rd16 = |off: usize| u16::from_le_bytes([data[off], data[off + 1]]);
        Some(Self {
            name,
            virtual_size: rd(offset + 8),
            virtual_address: rd(offset + 12),
            size_of_raw_data: rd(offset + 16),
            pointer_to_raw_data: rd(offset + 20),
            pointer_to_relocations: rd(offset + 24),
            pointer_to_line_numbers: rd(offset + 28),
            number_of_relocations: rd16(offset + 32),
            number_of_line_numbers: rd16(offset + 34),
            characteristics: rd(offset + 36),
        })
    }
}
