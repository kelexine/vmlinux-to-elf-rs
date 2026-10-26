// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `find_kallsyms_addresses_or_symbols` (3-mode heuristic).

#![forbid(unsafe_code)]

use crate::error::KallsymsError;

/// Result of `find_kallsyms_addresses_or_symbols`.
#[derive(Clone, Debug)]
pub struct AddressesOrOffsets {
    /// Absolute file offset of `kallsyms_addresses` (or `kallsyms_offsets`).
    pub offset: usize,
    /// `true` iff `CONFIG_KALLSYMS_BASE_RELATIVE` was inferred.
    pub has_base_relative: bool,
    /// `true` iff `CONFIG_KALLSYMS_ABSOLUTE_PERCPU` was inferred.
    pub has_absolute_percpu: bool,
    /// `kallsyms_relative_base` value, if `has_base_relative` is set.
    pub relative_base_address: Option<u64>,
    /// Decoded kernel addresses (one per symbol).
    pub kernel_addresses: Vec<u64>,
}

/// Parameters for one heuristic attempt.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct HeuristicParams {
    /// Whether `CONFIG_KALLSYMS_BASE_RELATIVE` is assumed.
    pub has_base_relative: bool,
    /// Whether offsets are pc-relative (v7.0+).
    pub pc_relative: bool,
    /// Whether we can skip this attempt if checks fail.
    pub can_skip: bool,
}

/// Decide the candidate heuristic list based on the kernel version.
pub fn heuristic_search_params(
    kernel_major: u32,
    version_string: &str,
    likely_has_base_relative: bool,
    override_relative_base: bool,
) -> Vec<HeuristicParams> {
    let version_lower = version_string.to_ascii_lowercase();
    let has_ia64 = version_lower.contains("ia64") || version_lower.contains("itanium");

    if kernel_major >= 7 {
        vec![
            HeuristicParams {
                has_base_relative: false,
                pc_relative: true,
                can_skip: true,
            },
            HeuristicParams {
                has_base_relative: false,
                pc_relative: false,
                can_skip: false,
            },
        ]
    } else if likely_has_base_relative && !has_ia64 {
        let mut v = vec![
            HeuristicParams {
                has_base_relative: true,
                pc_relative: false,
                can_skip: true,
            },
            HeuristicParams {
                has_base_relative: false,
                pc_relative: false,
                can_skip: false,
            },
        ];
        if override_relative_base {
            v = vec![HeuristicParams {
                has_base_relative: false,
                pc_relative: false,
                can_skip: false,
            }];
        }
        v
    } else {
        vec![
            HeuristicParams {
                has_base_relative: false,
                pc_relative: false,
                can_skip: true,
            },
            HeuristicParams {
                has_base_relative: false,
                pc_relative: false,
                can_skip: false,
            },
        ]
    }
}

/// Read the `kallsyms_addresses_or_offsets` array using the given
/// heuristic parameters. Returns the decoded addresses on success.
///
/// # Errors
/// Returns [`KallsymsError::Internal`] on invariant violations.
pub fn find_addresses_or_offsets(
    kernel_img: &[u8],
    is_64_bits: bool,
    is_big_endian: bool,
    num_symbols: usize,
    offset_table_element_size: usize,
    kallsyms_token_index_end: usize,
    kallsyms_num_syms_offset: usize,
    kernel_major: u32,
    kernel_minor: u32,
    version_string: &str,
    override_relative_base: bool,
    explicit_base_address: Option<u64>,
) -> Result<AddressesOrOffsets, KallsymsError> {
    let likely_has_base_relative = (kernel_major == 4 && kernel_minor >= 6)
        || (kernel_major > 4 && kernel_major < 7)
        || kernel_major >= 7;
    let likely_has_base_relative = likely_has_base_relative
        && !version_string.to_ascii_lowercase().contains("ia64")
        && !version_string.to_ascii_lowercase().contains("itanium");

    let params = heuristic_search_params(
        kernel_major,
        version_string,
        likely_has_base_relative,
        override_relative_base,
    );

    let address_byte_size = if is_64_bits {
        8
    } else {
        offset_table_element_size
    };
    let offset_byte_size = 4.min(offset_table_element_size);

    for params in &params {
        let mut position = if kernel_major > 6 || (kernel_major == 6 && kernel_minor >= 4) {
            // 6.4+: addresses come AFTER token_index.
            let align_size = if is_64_bits && !params.pc_relative {
                8
            } else {
                4
            };
            let mut pos = kallsyms_token_index_end;
            pos += (align_size - (pos % align_size)) % align_size;
            if params.has_base_relative {
                pos += num_symbols * offset_byte_size;
                pos += (align_size - (pos % align_size)) % align_size;
                pos += address_byte_size;
            } else if params.pc_relative {
                pos += num_symbols * offset_byte_size;
            } else {
                pos += num_symbols * address_byte_size;
            }
            pos
        } else {
            kallsyms_num_syms_offset
        };

        // Skip trailing zeros.
        while position > 0 {
            let prev_off = position - address_byte_size;
            if prev_off + address_byte_size > kernel_img.len() {
                break;
            }
            let prev = &kernel_img[prev_off..position];
            if prev != vec![0u8; address_byte_size].as_slice() {
                break;
            }
            position -= address_byte_size;
        }

        let mut relative_base: Option<u64> = None;
        if params.has_base_relative {
            position = position.saturating_sub(address_byte_size);
            let pos = position;
            if pos + address_byte_size > kernel_img.len() {
                continue;
            }
            relative_base = Some(read_uint(kernel_img, pos, address_byte_size, is_big_endian));
            while position > 0 {
                let prev_off = position - offset_byte_size;
                if prev_off + offset_byte_size > kernel_img.len() {
                    break;
                }
                if &kernel_img[prev_off..position] != vec![0u8; offset_byte_size].as_slice() {
                    break;
                }
                position -= offset_byte_size;
            }
            position = position.saturating_sub(num_symbols * offset_byte_size);
        } else if params.pc_relative {
            position = position.saturating_sub(num_symbols * offset_byte_size);
        } else {
            position = position.saturating_sub(num_symbols * address_byte_size);
        }

        // Parse the addresses / offsets.
        // Determine the per-entry byte size: for has_base_relative and
        // pc_relative cases, this is offset_byte_size (signed); for
        // the absolute-addresses case, it is address_byte_size.
        let entry_byte_size = if params.has_base_relative || params.pc_relative {
            offset_byte_size
        } else {
            address_byte_size
        };

        let mut tentative: Vec<i64> = Vec::with_capacity(num_symbols);
        for i in 0..num_symbols {
            let off = position + i * entry_byte_size;
            if off + entry_byte_size > kernel_img.len() {
                return Err(KallsymsError::Internal("kallsyms_offsets out of bounds"));
            }
            let v = match entry_byte_size {
                2 => {
                    let b = &kernel_img[off..off + 2];
                    if params.has_base_relative || params.pc_relative {
                        if is_big_endian {
                            i16::from_be_bytes([b[0], b[1]]) as i64
                        } else {
                            i16::from_le_bytes([b[0], b[1]]) as i64
                        }
                    } else {
                        if is_big_endian {
                            u16::from_be_bytes([b[0], b[1]]) as i64
                        } else {
                            u16::from_le_bytes([b[0], b[1]]) as i64
                        }
                    }
                },
                4 => {
                    let b = &kernel_img[off..off + 4];
                    if params.has_base_relative || params.pc_relative {
                        if is_big_endian {
                            i32::from_be_bytes([b[0], b[1], b[2], b[3]]) as i64
                        } else {
                            i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as i64
                        }
                    } else {
                        if is_big_endian {
                            u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as i64
                        } else {
                            u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as i64
                        }
                    }
                },
                8 => {
                    let b = &kernel_img[off..off + 8];
                    if is_big_endian {
                        u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) as i64
                    } else {
                        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) as i64
                    }
                },
                _ => return Err(KallsymsError::Internal("bad entry_byte_size")),
            };
            tentative.push(v);
        }

        // For base_relative: convert offsets to addresses.
        if params.can_skip
            && params.has_base_relative
            && tentative.len() >= 3
            && !(tentative[0] <= tentative[1] && tentative[1] <= tentative[2])
        {
            continue;
        }
        let mut addresses: Vec<u64> = Vec::with_capacity(num_symbols);
        if params.has_base_relative {
            let base = relative_base.unwrap_or(0);
            let negative_count = tentative.iter().filter(|&&v| v < 0).count();
            let threshold = (num_symbols + 1) / 2;
            if negative_count >= threshold {
                // ABSOLUTE_PERCPU
                for &v in &tentative {
                    if v < 0 {
                        addresses.push(base.wrapping_sub(1).wrapping_sub(v as u64));
                    } else {
                        addresses.push(v as u64);
                    }
                }
            } else {
                for &v in &tentative {
                    addresses.push(base.wrapping_add(v as u64));
                }
            }
        } else if params.pc_relative {
            // Read the ELF phdr to find the base address.
            for (i, &v) in tentative.iter().enumerate() {
                let addr = explicit_base_address
                    .unwrap_or(0)
                    .wrapping_add(v as u64)
                    .wrapping_sub(tentative[0] as u64)
                    .wrapping_add((i * offset_byte_size) as u64);
                addresses.push(addr);
            }
        } else {
            for &v in &tentative {
                addresses.push(v as u64);
            }
        }

        let null_count = addresses.iter().filter(|&&v| v == 0).count();
        if null_count * 5 >= num_symbols && params.can_skip {
            continue;
        }

        log::info!(
            "[+] Found {} at file offset 0x{:08x}",
            if params.has_base_relative {
                "kallsyms_offsets"
            } else {
                "kallsyms_addresses"
            },
            position
        );

        return Ok(AddressesOrOffsets {
            offset: position,
            has_base_relative: params.has_base_relative,
            has_absolute_percpu: false,
            relative_base_address: relative_base,
            kernel_addresses: addresses,
        });
    }
    Err(KallsymsError::Internal(
        "no heuristic produced a valid addresses table",
    ))
}

#[inline]
fn read_uint(data: &[u8], off: usize, size: usize, big_endian: bool) -> u64 {
    if off + size > data.len() {
        return 0;
    }
    match size {
        2 => {
            let b = &data[off..off + 2];
            if big_endian {
                u16::from_be_bytes([b[0], b[1]]) as u64
            } else {
                u16::from_le_bytes([b[0], b[1]]) as u64
            }
        },
        4 => {
            let b = &data[off..off + 4];
            if big_endian {
                u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64
            } else {
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64
            }
        },
        8 => {
            let b = &data[off..off + 8];
            if big_endian {
                u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            } else {
                u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            }
        },
        _ => 0,
    }
}
