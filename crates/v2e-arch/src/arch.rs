// SPDX-License-Identifier: GPL-3.0-or-later
//! Architecture enum + ArchitectureDetector.

#![forbid(unsafe_code)]

/// Architecture enum.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
pub enum ArchitectureName {
    /// mipsle = 1
    mipsle = 1,
    /// mipsbe = 2
    mipsbe = 2,
    /// mips64le = 3
    mips64le = 3,
    /// mips64be = 4
    mips64be = 4,
    /// x86 = 5
    x86 = 5,
    /// x86_64 = 6
    x86_64 = 6,
    /// powerpcbe = 7
    powerpcbe = 7,
    /// powerpcle = 8
    powerpcle = 8,
    /// armle = 9
    armle = 9,
    /// armbe = 10
    armbe = 10,
    /// aarch64 = 11
    aarch64 = 11,
    /// mips16e = 12
    mips16e = 12,
    /// superhle = 13
    superhle = 13,
    /// superhbe = 14
    superhbe = 14,
    /// sparc = 15
    sparc = 15,
    /// arcompact = 16
    arcompact = 16,
}

impl ArchitectureName {
    /// Readable name for the architecture.
    #[must_use]
    pub const fn readable_name(self) -> &'static str {
        match self {
            ArchitectureName::x86_64 => "64-bit x86",
            ArchitectureName::x86 => "32-bit x86",
            ArchitectureName::armle => "Little-endian ARM",
            ArchitectureName::armbe => "Big-endian ARM",
            ArchitectureName::aarch64 => "Little-endian ARM64",
            ArchitectureName::mipsle => "Little-endian MIPS",
            ArchitectureName::mipsbe => "Big-endian MIPS",
            ArchitectureName::mips64be => "Big-endian MIPS64",
            ArchitectureName::mips64le => "Little-endian MIPS64",
            ArchitectureName::mips16e => "Big-endian MIPS16e",
            ArchitectureName::powerpcbe => "Big-endian PowerPC",
            ArchitectureName::powerpcle => "Little-endian PowerPC",
            ArchitectureName::superhle => "Little-endian SuperH",
            ArchitectureName::superhbe => "Big-endian SuperH",
            ArchitectureName::sparc => "SPARC",
            ArchitectureName::arcompact => "ARCompact",
        }
    }
}

/// Error raised when no architecture reaches the 100-prologue threshold.
#[derive(Debug, thiserror::Error)]
#[error("The architecture could not be guessed successfully")]
pub struct ArchitectureGuessError;

/// Result of a successful `ArchitectureDetector::guess` call.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ArchitectureDetectionResult {
    /// Which architecture was guessed.
    pub architecture_name: ArchitectureName,
    /// The `EM_*` value to write into the ELF `e_machine` field.
    pub elf_machine: u16,
    /// Whether the architecture is 64-bit.
    pub is_64_bit: bool,
    /// Whether the architecture is big-endian.
    pub is_big_endian: bool,
}

impl ArchitectureDetectionResult {
    /// Construct from an architecture name.
    #[must_use]
    pub fn from_name(name: ArchitectureName) -> Self {
        // (elf_machine, is_64_bit, is_big_endian)
        let (elf_machine, is_64_bit, is_big_endian) = match name {
            ArchitectureName::mipsle => (8, false, false),
            ArchitectureName::mipsbe | ArchitectureName::mips16e => (8, false, true),
            ArchitectureName::mips64le => (8, true, false),
            ArchitectureName::mips64be => (8, true, true),
            ArchitectureName::x86 => (3, false, false),
            ArchitectureName::x86_64 => (62, true, false),
            ArchitectureName::powerpcbe => (20, false, true),
            ArchitectureName::powerpcle => (20, false, false),
            ArchitectureName::armbe => (40, false, true),
            ArchitectureName::armle => (40, false, false),
            ArchitectureName::superhle => (42, false, false),
            ArchitectureName::superhbe => (42, false, true),
            ArchitectureName::aarch64 => (183, true, false),
            ArchitectureName::sparc => (2, false, true),
            ArchitectureName::arcompact => (93, false, false),
        };
        Self {
            architecture_name: name,
            elf_machine,
            is_64_bit,
            is_big_endian,
        }
    }
}

/// Top-level detector.
pub struct ArchitectureDetector;

impl ArchitectureDetector {
    /// Main entry point.
    /// Tries `_guess_architecture_special` first (UEFI `MZ` + `ARMd`),
    /// then `_guess_architecture_common` (prologue regex counter).
    ///
    /// Returns `ArchitectureGuessError` if no architecture reaches the
    /// 100-prologue threshold.
    ///
    /// # Errors
    /// Returns [`ArchitectureGuessError`] when no architecture reaches the
    /// 100-prologue threshold.
    pub fn guess(binary: &[u8]) -> Result<ArchitectureDetectionResult, ArchitectureGuessError> {
        if let Some(name) = Self::guess_special(binary) {
            return Ok(ArchitectureDetectionResult::from_name(name));
        }
        if let Some(name) = Self::guess_common(binary) {
            return Ok(ArchitectureDetectionResult::from_name(name));
        }
        Err(ArchitectureGuessError)
    }

    /// Mirror of `_guess_architecture_special` — detect UEFI boot stub.
    #[must_use]
    fn guess_special(binary: &[u8]) -> Option<ArchitectureName> {
        if binary.len() >= 0x3c + 4 && &binary[..2] == b"MZ" {
            if &binary[0x38..0x3c] == b"ARMd" {
                return Some(ArchitectureName::aarch64);
            }
        }
        None
    }

    /// Mirror of `_guess_architecture_common` — count prologue matches
    /// per architecture, return the winner iff it has ≥100 hits.
    #[must_use]
    fn guess_common(binary: &[u8]) -> Option<ArchitectureName> {
        let mut best: Option<(ArchitectureName, usize)> = None;
        for (arch, pat) in crate::prologues::prologue_patterns() {
            let count = pat.count_all(binary);
            if let Some((_, c)) = best {
                if count > c {
                    best = Some((arch, count));
                }
            } else {
                best = Some((arch, count));
            }
        }
        best.and_then(|(a, c)| if c >= 100 { Some(a) } else { None })
    }
}
