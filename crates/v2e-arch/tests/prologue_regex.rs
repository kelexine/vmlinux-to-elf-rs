// SPDX-License-Identifier: GPL-3.0-or-later
// Rust port of marin-m/vmlinux-to-elf (https://github.com/marin-m/vmlinux-to-elf)
//
//! The hand-built prologue patterns must count exactly what the reference's
//! regexes count. This test takes the reference's regex strings verbatim
//! (`architecture_to_prologue_regex` in `architecture_detecter.py`), compiles
//! them with the real `regex` crate (DOTALL, bytes, no Unicode), and compares
//! match counts on adversarial data.
//!
//! It exists because the first port hand-translated three of these regexes
//! incorrectly (`armle`, `armbe`, `x86`), which silently broke detection of
//! every 32-bit ARM and x86 kernel.

#![forbid(unsafe_code)]

use regex::bytes::RegexBuilder;
use v2e_arch::ArchitectureName;
use v2e_arch::prologues::{Element, Pattern, prologue_patterns};

/// `(architecture, regex)` exactly as written in the reference tool.
fn reference_regexes() -> Vec<(ArchitectureName, &'static str)> {
    use ArchitectureName::*;
    vec![
        (mipsle, r".\xFF\xBD\x27..[\xA0-\xBF]\xAF"),
        (mipsbe, r"\x27\xBD\xFF.\xAF[\xA0-\xBF].."),
        (mips64le, r".\xFF\xBD\x67..[\xA0-\xBF]\xFF"),
        (mips64be, r"\x67\xBD\xFF.\xFF[\xA0-\xBF].."),
        (x86, r"\x55\x89\xE5(?:\x83\xEC|\x57\x56)"),
        (x86_64, r"\x55\x48\x89\xE5"),
        (powerpcbe, r"\x7C\x08\x02\xA6"),
        (powerpcle, r"\xA6\x02\x08\x7C"),
        (armbe, r"\xE9\x2D..(?:[\xE0-\xEF]...){2}"),
        (armle, r"\x2D\xE9(?:...[\xE0-\xEF]){2}"),
        (mips16e, r"\xf0\x08\x64.\x01."),
        (superhle, r"\xF6\x69\x0B\x00\xF6\x68"),
        (superhbe, r"\x69\xF6\x00\x0B\x68\xF6"),
        (aarch64, r"\xc0\x03\x5f\xd6"),
        (sparc, r"\x81\xC7\xE0\x08\x81\xE8"),
        (arcompact, r"\xf1\xc0.\x1c\x48[\xb0-\xbf]"),
    ]
}

/// Every byte that appears in any pattern, plus some noise, so partial and
/// full matches are frequent.
const ALPHABET: &[u8] = &[
    0x00, 0x01, 0x0A, 0x1C, 0x27, 0x2D, 0x48, 0x55, 0x56, 0x57, 0x67, 0x7C, 0x81, 0x83, 0x89, 0xA0,
    0xA6, 0xAF, 0xB0, 0xBD, 0xBF, 0xC0, 0xC7, 0xE0, 0xE5, 0xE8, 0xE9, 0xEC, 0xEF, 0xF0, 0xF1, 0xFF,
    0x08, 0x02, 0x03, 0x0B, 0x5F, 0x64, 0x68, 0x69, 0xD6, 0xF6,
];

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
}

fn biased_buffer(rng: &mut Lcg, len: usize) -> Vec<u8> {
    (0..len)
        .map(|_| ALPHABET[(rng.next() as usize) % ALPHABET.len()])
        .collect()
}

/// One byte string accepted by `pattern`'s elements.
fn sample(pattern: &Pattern, rng: &mut Lcg) -> Vec<u8> {
    let mut out = Vec::new();
    for element in pattern.elements() {
        match element {
            Element::Any => out.push(rng.next() as u8),
            Element::Lit(b) => out.push(*b),
            Element::Range(lo, hi) => {
                let span = u64::from(*hi - *lo) + 1;
                out.push(*lo + (rng.next() % span) as u8);
            },
            Element::Alt(alternatives) => {
                let pick = &alternatives[(rng.next() as usize) % alternatives.len()];
                out.extend_from_slice(pick);
            },
        }
    }
    out
}

/// Overwrite `count` random spots of `data` with samples (neighbours may
/// overlap, which exercises the non-overlapping counting rule).
fn inject(data: &mut [u8], pattern: &Pattern, rng: &mut Lcg, count: usize) {
    for _ in 0..count {
        let s = sample(pattern, rng);
        if s.len() >= data.len() {
            continue;
        }
        let at = (rng.next() as usize) % (data.len() - s.len());
        data[at..at + s.len()].copy_from_slice(&s);
    }
}

#[test]
fn every_pattern_counts_exactly_like_the_reference_regex() {
    let patterns = prologue_patterns();
    assert_eq!(
        patterns.len(),
        reference_regexes().len(),
        "one pattern per reference regex"
    );

    let mut rng = Lcg(0x5EED_1234_ABCD_0042);

    for ((arch, regex_src), (parity_arch, pattern)) in reference_regexes().iter().zip(&patterns) {
        assert_eq!(arch, parity_arch, "pattern order must follow the reference");
        let re = RegexBuilder::new(regex_src)
            .unicode(false)
            .dot_matches_new_line(true)
            .build()
            .unwrap_or_else(|e| panic!("bad reference regex for {arch:?}: {e}"));

        // Biased noise plus valid samples of this very pattern, so matches,
        // near-misses and overlapping neighbours all occur.
        let buffers: Vec<Vec<u8>> = (0..200)
            .map(|i| {
                let mut buf = biased_buffer(&mut rng, 512 + (i % 7) * 977);
                inject(&mut buf, pattern, &mut rng, 1 + i % 25);
                buf
            })
            .collect();

        let mut total_matches = 0usize;
        for (n, data) in buffers.iter().enumerate() {
            let expected = re.find_iter(data).count();
            let got = pattern.count_all(data);
            assert_eq!(
                got,
                expected,
                "{arch:?}: buffer #{n} (len {}) — Rust counted {got}, regex counted {expected}",
                data.len()
            );
            total_matches += expected;
        }
        assert!(
            total_matches > 0,
            "{arch:?}: the corpus never produced a match, so this check proved nothing"
        );
    }
}

#[test]
fn newline_bytes_are_matched_by_the_wildcard_like_dotall() {
    // `.` must match 0x0A: the reference uses re.DOTALL.
    let (_, x) = prologue_patterns()
        .into_iter()
        .find(|(a, _)| *a == ArchitectureName::mipsle)
        .unwrap();
    let data = [0x0A, 0xFF, 0xBD, 0x27, 0x0A, 0x0A, 0xA5, 0xAF];
    assert_eq!(x.count_all(&data), 1);
}
