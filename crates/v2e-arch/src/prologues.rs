// SPDX-License-Identifier: GPL-3.0-or-later

//! Function-prologue byte signatures (`architecture_to_prologue_regex`).
//!
//! Each entry is `(ArchitectureName, pattern_bytes)` where `pattern_bytes`
//! is the *raw* regex byte pattern. The matcher
//! supports the limited subset of regex metacharacters actually used:
//! `.`, `[\xNN-\xNN]`, literal bytes, and `[\xb0-\xbf]`-style ranges.

#![forbid(unsafe_code)]

use crate::ArchitectureName;

/// One step of a byte pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Element {
    /// `.` (the reference uses DOTALL, so it matches every byte, including `\n`).
    Any,
    /// A single literal byte.
    Lit(u8),
    /// `[\xLO-\xHI]` — one byte in the inclusive range.
    Range(u8, u8),
    /// `(?:ALT1|ALT2|…)` — any one of the byte strings.
    Alt(Vec<Vec<u8>>),
}

/// Literal bytes, in order.
fn lits(bytes: &[u8]) -> Vec<Element> {
    bytes.iter().map(|&b| Element::Lit(b)).collect()
}

/// `n` copies of `group` (`(?:group){n}`).
fn repeat(n: usize, group: &[Element]) -> Vec<Element> {
    (0..n).flat_map(|_| group.iter().cloned()).collect()
}

/// A compiled byte pattern with the same leftmost, non-overlapping matching as
/// `re.findall` on a `bytes` object.
#[derive(Clone, Debug)]
pub struct Pattern {
    elements: Vec<Element>,
    anchor: Option<(usize, u8)>,
}

impl Pattern {
    /// Build a pattern from its elements.
    #[must_use]
    pub fn new(elements: Vec<Element>) -> Self {
        // Elements before the first literal must each consume exactly one
        // byte for the element index to equal the byte offset.
        let anchor = elements
            .iter()
            .enumerate()
            .take_while(|(_, e)| !matches!(e, Element::Alt(_)))
            .find_map(|(i, e)| match e {
                Element::Lit(b) => Some((i, *b)),
                _ => None,
            });
        Self { elements, anchor }
    }

    /// The elements this pattern is built from (read-only).
    #[must_use]
    pub fn elements(&self) -> &[Element] {
        &self.elements
    }

    /// Length of the match starting exactly at `offset`, or `None`.
    #[must_use]
    pub fn matches_at(&self, data: &[u8], offset: usize) -> Option<usize> {
        self.match_from(0, data, offset).map(|end| end - offset)
    }

    /// Match `elements[idx..]` at `pos`; returns the end position. Alternation
    /// backtracks exactly like a regex engine would.
    fn match_from(&self, idx: usize, data: &[u8], pos: usize) -> Option<usize> {
        let Some(element) = self.elements.get(idx) else {
            return Some(pos);
        };
        match element {
            Element::Any => {
                data.get(pos)?;
                self.match_from(idx + 1, data, pos + 1)
            },
            Element::Lit(b) => {
                if *data.get(pos)? == *b {
                    self.match_from(idx + 1, data, pos + 1)
                } else {
                    None
                }
            },
            Element::Range(lo, hi) => {
                if (*lo..=*hi).contains(data.get(pos)?) {
                    self.match_from(idx + 1, data, pos + 1)
                } else {
                    None
                }
            },
            Element::Alt(alternatives) => alternatives.iter().find_map(|alt| {
                let end = pos.checked_add(alt.len())?;
                if data.get(pos..end)? == alt.as_slice() {
                    self.match_from(idx + 1, data, end)
                } else {
                    None
                }
            }),
        }
    }

    /// Count leftmost, non-overlapping matches in `data`.
    #[must_use]
    pub fn count_all(&self, data: &[u8]) -> usize {
        if self.elements.is_empty() {
            return 0;
        }
        let mut count = 0usize;
        let mut i = 0usize;
        while i < data.len() {
            if let Some((offset, byte)) = self.anchor {
                // Jump to the next start whose anchor byte lines up.
                let Some(search) = data.get(i + offset..) else {
                    break;
                };
                match memchr::memchr(byte, search) {
                    Some(skip) => i += skip,
                    None => break,
                }
            }
            match self.matches_at(data, i) {
                // Elements always consume at least one byte, so `len >= 1`.
                Some(len) if len > 0 => {
                    count += 1;
                    i += len;
                },
                _ => i += 1,
            }
        }
        count
    }
}

/// All `(architecture, pattern)` pairs, in the reference's dictionary order
/// (which matters for tie-breaking: the first architecture with the maximum
/// count wins).
#[must_use]
pub fn prologue_patterns() -> Vec<(ArchitectureName, Pattern)> {
    use ArchitectureName::{
        aarch64, arcompact, armbe, armle, mips16e, mips64be, mips64le, mipsbe, mipsle, powerpcbe,
        powerpcle, sparc, superhbe, superhle, x86, x86_64,
    };
    use Element::{Alt, Any, Lit, Range};

    let patterns: Vec<(ArchitectureName, Vec<Element>)> = vec![
        // rb'.\xFF\xBD\x27..[\xA0-\xBF]\xAF'
        (
            mipsle,
            vec![
                Any,
                Lit(0xFF),
                Lit(0xBD),
                Lit(0x27),
                Any,
                Any,
                Range(0xA0, 0xBF),
                Lit(0xAF),
            ],
        ),
        // rb'\x27\xBD\xFF.\xAF[\xA0-\xBF]..'
        (
            mipsbe,
            vec![
                Lit(0x27),
                Lit(0xBD),
                Lit(0xFF),
                Any,
                Lit(0xAF),
                Range(0xA0, 0xBF),
                Any,
                Any,
            ],
        ),
        // rb'.\xFF\xBD\x67..[\xA0-\xBF]\xFF'
        (
            mips64le,
            vec![
                Any,
                Lit(0xFF),
                Lit(0xBD),
                Lit(0x67),
                Any,
                Any,
                Range(0xA0, 0xBF),
                Lit(0xFF),
            ],
        ),
        // rb'\x67\xBD\xFF.\xFF[\xA0-\xBF]..'
        (
            mips64be,
            vec![
                Lit(0x67),
                Lit(0xBD),
                Lit(0xFF),
                Any,
                Lit(0xFF),
                Range(0xA0, 0xBF),
                Any,
                Any,
            ],
        ),
        // rb'\x55\x89\xE5(?:\x83\xEC|\x57\x56)'
        (
            x86,
            [
                lits(&[0x55, 0x89, 0xE5]),
                vec![Alt(vec![vec![0x83, 0xEC], vec![0x57, 0x56]])],
            ]
            .concat(),
        ),
        // rb'\x55\x48\x89\xE5'
        (x86_64, lits(&[0x55, 0x48, 0x89, 0xE5])),
        // rb'\x7C\x08\x02\xA6'
        (powerpcbe, lits(&[0x7C, 0x08, 0x02, 0xA6])),
        // rb'\xA6\x02\x08\x7C'
        (powerpcle, lits(&[0xA6, 0x02, 0x08, 0x7C])),
        // rb'\xE9\x2D..(?:[\xE0-\xEF]...){2}'
        (
            armbe,
            [
                lits(&[0xE9, 0x2D]),
                vec![Any, Any],
                repeat(2, &[Range(0xE0, 0xEF), Any, Any, Any]),
            ]
            .concat(),
        ),
        // rb'\x2D\xE9(?:...[\xE0-\xEF]){2}'
        (
            armle,
            [
                lits(&[0x2D, 0xE9]),
                repeat(2, &[Any, Any, Any, Range(0xE0, 0xEF)]),
            ]
            .concat(),
        ),
        // rb'\xf0\x08\x64.\x01.'
        (
            mips16e,
            [lits(&[0xF0, 0x08, 0x64]), vec![Any, Lit(0x01), Any]].concat(),
        ),
        // rb'\xF6\x69\x0B\x00\xF6\x68' (an epilogue)
        (superhle, lits(&[0xF6, 0x69, 0x0B, 0x00, 0xF6, 0x68])),
        // rb'\x69\xF6\x00\x0B\x68\xF6' (an epilogue)
        (superhbe, lits(&[0x69, 0xF6, 0x00, 0x0B, 0x68, 0xF6])),
        // rb'\xc0\x03\x5f\xd6' (an epilogue)
        (aarch64, lits(&[0xC0, 0x03, 0x5F, 0xD6])),
        // rb'\x81\xC7\xE0\x08\x81\xE8' (an epilogue)
        (sparc, lits(&[0x81, 0xC7, 0xE0, 0x08, 0x81, 0xE8])),
        // b'\xf1\xc0.\x1c\x48[\xb0-\xbf]'  (push_s blink; st.a r??, [sp, -??])
        (
            arcompact,
            [
                lits(&[0xF1, 0xC0]),
                vec![Any],
                lits(&[0x1C, 0x48]),
                vec![Range(0xB0, 0xBF)],
            ]
            .concat(),
        ),
    ];

    patterns
        .into_iter()
        .map(|(arch, elements)| (arch, Pattern::new(elements)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(arch: ArchitectureName) -> Pattern {
        prologue_patterns()
            .into_iter()
            .find(|(a, _)| *a == arch)
            .map(|(_, p)| p)
            .expect("pattern exists")
    }

    #[test]
    fn armle_matches_push_with_two_conditional_groups() {
        // 2D E9 | aa bb cc E1 | dd ee ff E5  (10 bytes)
        let hit = [0x2D, 0xE9, 1, 2, 3, 0xE1, 4, 5, 6, 0xE5];
        assert_eq!(pat(ArchitectureName::armle).matches_at(&hit, 0), Some(10));
        // Second group's condition byte out of range -> no match.
        let miss = [0x2D, 0xE9, 1, 2, 3, 0xE1, 4, 5, 6, 0x05];
        assert_eq!(pat(ArchitectureName::armle).matches_at(&miss, 0), None);
    }

    #[test]
    fn armbe_is_twelve_bytes_with_no_extra_wildcard() {
        // E9 2D . . | [E0-EF] . . . | [E0-EF] . . .
        let hit = [0xE9, 0x2D, 9, 9, 0xE2, 1, 2, 3, 0xEF, 4, 5, 6];
        assert_eq!(pat(ArchitectureName::armbe).matches_at(&hit, 0), Some(12));
    }

    #[test]
    fn x86_accepts_either_alternative() {
        let p = pat(ArchitectureName::x86);
        assert_eq!(p.matches_at(&[0x55, 0x89, 0xE5, 0x83, 0xEC], 0), Some(5));
        assert_eq!(p.matches_at(&[0x55, 0x89, 0xE5, 0x57, 0x56], 0), Some(5));
        assert_eq!(p.matches_at(&[0x55, 0x89, 0xE5, 0x83, 0x56], 0), None);
    }

    #[test]
    fn counting_is_non_overlapping_and_leftmost() {
        let p = Pattern::new(lits(&[1, 1]));
        assert_eq!(p.count_all(&[1, 1, 1, 1, 1]), 2);
        assert_eq!(p.count_all(&[]), 0);
        assert_eq!(Pattern::new(vec![]).count_all(&[1, 2, 3]), 0);
    }

    #[test]
    fn matching_never_reads_past_the_buffer() {
        for arch_pat in prologue_patterns() {
            for len in 0..14 {
                let data = vec![0x2D; len];
                let _ = arch_pat.1.count_all(&data);
                let _ = arch_pat.1.matches_at(&data, len);
            }
        }
    }
}
