// SPDX-License-Identifier: GPL-3.0-or-later
//! ElfMachine(IntEnum)

#![forbid(unsafe_code)]

/// ElfMachine enum
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ElfMachine {
    /// `EM_NONE = 0`.
    None,
    /// `EM_SPARC = 2`.
    Sparc,
    /// `EM_386 = 3`.
    I386,
    /// `EM_PPC = 20`.
    Ppc,
    /// `EM_ARM = 40`.
    Arm,
    /// `EM_SH = 42`.
    Sh,
    /// `EM_X86_64 = 62`.
    X86_64,
    /// `EM_ARCOMPACT = 93`.
    Arcompact,
    /// `EM_AARCH64 = 183`.
    Aarch64,
    /// Catch-all for any other `EM_*` value encountered in the wild.
    Other(u16),
}

impl ElfMachine {
    /// Convert to the integer value written into `e_machine`.
    #[must_use]
    pub const fn to_int(self) -> u16 {
        match self {
            ElfMachine::None => 0,
            ElfMachine::Sparc => 2,
            ElfMachine::I386 => 3,
            ElfMachine::Ppc => 20,
            ElfMachine::Arm => 40,
            ElfMachine::Sh => 42,
            ElfMachine::X86_64 => 62,
            ElfMachine::Arcompact => 93,
            ElfMachine::Aarch64 => 183,
            ElfMachine::Other(v) => v,
        }
    }

    /// Convert from an integer `e_machine` value.
    #[must_use]
    pub const fn from_int(v: u16) -> Self {
        match v {
            0 => ElfMachine::None,
            2 => ElfMachine::Sparc,
            3 => ElfMachine::I386,
            20 => ElfMachine::Ppc,
            40 => ElfMachine::Arm,
            42 => ElfMachine::Sh,
            62 => ElfMachine::X86_64,
            93 => ElfMachine::Arcompact,
            183 => ElfMachine::Aarch64,
            other => ElfMachine::Other(other),
        }
    }
}

impl From<u16> for ElfMachine {
    #[inline]
    fn from(v: u16) -> Self {
        Self::from_int(v)
    }
}

impl From<ElfMachine> for u16 {
    #[inline]
    fn from(m: ElfMachine) -> Self {
        m.to_int()
    }
}
