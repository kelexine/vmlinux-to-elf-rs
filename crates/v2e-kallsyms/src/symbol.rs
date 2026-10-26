// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `KallsymsSymbol` + `KallsymsSymbolType`.

#![forbid(unsafe_code)]

/// Symbol type letter.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum KallsymsSymbolType {
    /// `A` — absolute.
    Absolute,
    /// `B` — BSS.
    Bss,
    /// `D` — data.
    Data,
    /// `R` — read-only data.
    Rodata,
    /// `T` — text.
    Text,
    /// `V` — weak object with default.
    WeakObjectWithDefault,
    /// `W` — weak symbol with default.
    WeakSymbolWithDefault,
    /// `G` — small data.
    SmallData,
    /// `I` — indirect function.
    IndirectFunction,
    /// `N` — debugging.
    Debugging,
    /// `P` — stack unwind.
    StackUnwind,
    /// `C` — common.
    Common,
    /// `S` — small BSS.
    SmallBss,
    /// `U` — undefined.
    Undefined,
    /// `u` — unique global.
    UniqueGlobal,
    /// `v` — weak object.
    WeakObject,
    /// `w` — weak symbol.
    WeakSymbol,
    /// `-` — stabs debug.
    StabsDebug,
    /// `?` — unknown.
    Unknown,
}

impl KallsymsSymbolType {
    /// Convert to the single-letter representation used in `kallsyms` symbol-type output.
    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            KallsymsSymbolType::Absolute => 'A',
            KallsymsSymbolType::Bss => 'B',
            KallsymsSymbolType::Data => 'D',
            KallsymsSymbolType::Rodata => 'R',
            KallsymsSymbolType::Text => 'T',
            KallsymsSymbolType::WeakObjectWithDefault => 'V',
            KallsymsSymbolType::WeakSymbolWithDefault => 'W',
            KallsymsSymbolType::SmallData => 'G',
            KallsymsSymbolType::IndirectFunction => 'I',
            KallsymsSymbolType::Debugging => 'N',
            KallsymsSymbolType::StackUnwind => 'P',
            KallsymsSymbolType::Common => 'C',
            KallsymsSymbolType::SmallBss => 'S',
            KallsymsSymbolType::Undefined => 'U',
            KallsymsSymbolType::UniqueGlobal => 'u',
            KallsymsSymbolType::WeakObject => 'v',
            KallsymsSymbolType::WeakSymbol => 'w',
            KallsymsSymbolType::StabsDebug => '-',
            KallsymsSymbolType::Unknown => '?',
        }
    }

    /// Convert from a single ASCII letter (case-sensitive). Returns `None`
    /// if the letter does not correspond to any `nm`/`kallsyms` type.
    #[must_use]
    pub fn from_letter(c: char) -> Option<Self> {
        Some(match c {
            'A' => KallsymsSymbolType::Absolute,
            'B' => KallsymsSymbolType::Bss,
            'D' => KallsymsSymbolType::Data,
            'R' => KallsymsSymbolType::Rodata,
            'T' => KallsymsSymbolType::Text,
            'V' => KallsymsSymbolType::WeakObjectWithDefault,
            'W' => KallsymsSymbolType::WeakSymbolWithDefault,
            'G' => KallsymsSymbolType::SmallData,
            'I' => KallsymsSymbolType::IndirectFunction,
            'N' => KallsymsSymbolType::Debugging,
            'P' => KallsymsSymbolType::StackUnwind,
            'C' => KallsymsSymbolType::Common,
            'S' => KallsymsSymbolType::SmallBss,
            'U' => KallsymsSymbolType::Undefined,
            'u' => KallsymsSymbolType::UniqueGlobal,
            'v' => KallsymsSymbolType::WeakObject,
            'w' => KallsymsSymbolType::WeakSymbol,
            '-' => KallsymsSymbolType::StabsDebug,
            '?' => KallsymsSymbolType::Unknown,
            _ => return None,
        })
    }
}

/// A recovered kallsyms symbol.
///
/// - `name`: symbol name without the leading type letter.
/// - `file_offset`: not populated by the finder itself; left `None` for now.
/// - `virtual_address`: decoded address from `kallsyms_addresses` / `kallsyms_offsets` + `kallsyms_relative_base`.
/// - `symbol_type`: the `nm` letter (canonical, uppercase).
/// - `type_letter`: the original case letter from the kallsyms table.
/// - `is_global`: `True` iff the letter is uppercase OR one of `u/v/w/V/W`.
#[derive(Clone, Debug, Default)]
pub struct KallsymsSymbol {
    /// Symbol name (without the leading type letter).
    pub name: String,
    /// File offset within the input (currently unused)
    pub file_offset: Option<usize>,
    /// Decoded virtual address.
    pub virtual_address: u64,
    /// Decoded symbol type (canonical, uppercase).
    pub symbol_type: Option<KallsymsSymbolType>,
    /// Original case letter from the kallsyms table.
    pub type_letter: char,
    /// Whether the symbol is global (uppercase type letter, or `u/v/w`).
    pub is_global: bool,
}
