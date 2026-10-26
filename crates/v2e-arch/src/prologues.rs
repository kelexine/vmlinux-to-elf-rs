// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Function-prologue byte signatures
//!
//! Each entry is `(ArchitectureName, pattern_bytes)` where `pattern_bytes`
//! is the *raw* regex byte pattern. The matcher
//! supports the limited subset of regex metacharacters actually used:
//! `.`, `[\xNN-\xNN]`, literal bytes, and `[\xb0-\xbf]`-style ranges.

#![forbid(unsafe_code)]

use crate::ArchitectureName;

/// A compiled byte pattern. Equivalent to a small subset of `regex::bytes::Regex`.
#[derive(Clone, Debug)]
pub struct Pattern {
    elements: Vec<Element>,
}

#[derive(Clone, Debug)]
enum Element {
    /// Match any single byte.
    AnyByte,
    /// Match one specific byte.
    Literal(u8),
    /// Match one byte in the inclusive range.
    Range(u8, u8),
}

impl Pattern {
    /// Compile a raw regex byte pattern. Recognized metacharacters:
    /// - `.` — any byte
    /// - `[\xNN-\xMM]` — byte range
    /// - `[\xNN]` — single-byte class (rare in practice)
    /// - literal bytes — match themselves
    ///
    /// Any other metacharacter (e.g. `*`, `+`, `?`) is treated as a
    /// literal byte.
    ///
    /// # Panics
    /// Panics if the pattern contains an unbalanced `[` or `]`.
    #[must_use]
    pub fn compile(pat: &[u8]) -> Self {
        let mut elements: Vec<Element> = Vec::new();
        let mut i = 0;
        while i < pat.len() {
            match pat[i] {
                b'.' => {
                    elements.push(Element::AnyByte);
                    i += 1;
                },
                b'[' => {
                    // Find the closing ']'.
                    let mut j = i + 1;
                    while j < pat.len() && pat[j] != b']' {
                        j += 1;
                    }
                    assert!(j < pat.len(), "unbalanced '[' in pattern");
                    let class = &pat[i + 1..j];
                    // Expect one element: either "X-Y" (range) or "X" (literal).
                    if class.len() == 1 {
                        elements.push(Element::Literal(class[0]));
                    } else if class.len() == 3 && class[1] == b'-' {
                        elements.push(Element::Range(class[0], class[2]));
                    } else {
                        for &b in class {
                            elements.push(Element::Literal(b));
                        }
                    }
                    i = j + 1;
                },
                b => {
                    elements.push(Element::Literal(b));
                    i += 1;
                },
            }
        }
        Self { elements }
    }

    /// Try to match the pattern starting at `offset` in `data`. Returns
    /// `true` iff the pattern matches exactly `self.elements.len()` bytes.
    #[must_use]
    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.elements.len() > data.len() {
            return false;
        }
        for (i, el) in self.elements.iter().enumerate() {
            let b = data[offset + i];
            match el {
                Element::AnyByte => {},
                Element::Literal(l) => {
                    if b != *l {
                        return false;
                    }
                },
                Element::Range(lo, hi) => {
                    if !(*lo..=*hi).contains(&b) {
                        return false;
                    }
                },
            }
        }
        true
    }

    /// Count all non-overlapping matches of this pattern in `data`.
    #[must_use]
    pub fn count_all(&self, data: &[u8]) -> usize {
        if self.elements.is_empty() || data.len() < self.elements.len() {
            return 0;
        }
        let mut count = 0usize;
        let mut i = 0usize;
        let last = data.len() - self.elements.len();
        while i <= last {
            if self.matches_at(data, i) {
                count += 1;
                // Non-overlapping advance.
                i += self.elements.len().max(1);
            } else {
                i += 1;
            }
        }
        count
    }
}

/// All (architecture, pattern) pairs from `architecture_to_prologue_regex`.
#[must_use]
pub fn prologue_patterns() -> Vec<(ArchitectureName, Pattern)> {
    use ArchitectureName::*;
    [
        (
            mipsle,
            Pattern::compile(&[
                0x2e, 0xff, 0xbd, 0x27, 0x2e, 0x2e, b'[', 0xa0, b'-', 0xbf, b']', 0xaf,
            ]),
        ),
        (
            mipsbe,
            Pattern::compile(&[
                0x27, 0xbd, 0xff, 0x2e, 0xaf, b'[', 0xa0, b'-', 0xbf, b']', 0x2e, 0x2e,
            ]),
        ),
        (
            mips64le,
            Pattern::compile(&[
                0x2e, 0xff, 0xbd, 0x67, 0x2e, 0x2e, b'[', 0xa0, b'-', 0xbf, b']', 0xff,
            ]),
        ),
        (
            mips64be,
            Pattern::compile(&[
                0x67, 0xbd, 0xff, 0x2e, 0xff, b'[', 0xa0, b'-', 0xbf, b']', 0x2e, 0x2e,
            ]),
        ),
        (
            x86,
            Pattern::compile(&[
                0x55, 0x89, 0xe5, b'[', 0x83, b'-', 0x83, b']', 0xec, 0x57, 0x56,
            ]),
        ),
        (x86_64, Pattern::compile(&[0x55, 0x48, 0x89, 0xe5])),
        (powerpcbe, Pattern::compile(&[0x7c, 0x08, 0x02, 0xa6])),
        (powerpcle, Pattern::compile(&[0xa6, 0x02, 0x08, 0x7c])),
        (
            armbe,
            Pattern::compile(&[
                0xe9, 0x2d, 0x2e, 0x2e, b'[', 0xe0, b'-', 0xef, b']', 0x2e, 0x2e, 0x2e, 0x2e, b'[',
                0xe0, b'-', 0xef, b']', 0x2e, 0x2e, 0x2e,
            ]),
        ),
        (
            armle,
            Pattern::compile(&[
                0x2d, 0xe9, b'[', 0x2e, 0x2e, 0x2e, b'[', 0xe0, b'-', 0xef, b']', b']',
            ]),
        ),
        (
            mips16e,
            Pattern::compile(&[0xf0, 0x08, 0x64, 0x2e, 0x01, 0x2e]),
        ),
        (
            superhle,
            Pattern::compile(&[0xf6, 0x69, 0x0b, 0x00, 0xf6, 0x68]),
        ),
        (
            superhbe,
            Pattern::compile(&[0x69, 0xf6, 0x00, 0x0b, 0x68, 0xf6]),
        ),
        (aarch64, Pattern::compile(&[0xc0, 0x03, 0x5f, 0xd6])),
        (
            sparc,
            Pattern::compile(&[0x81, 0xc7, 0xe0, 0x08, 0x81, 0xe8]),
        ),
        (
            arcompact,
            Pattern::compile(&[0xf1, 0xc0, 0x2e, 0x1c, 0x48, b'[', 0xb0, b'-', 0xbf, b']']),
        ),
    ]
    .into_iter()
    .collect()
}
