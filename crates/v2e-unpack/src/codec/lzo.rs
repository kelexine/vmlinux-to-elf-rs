// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Pure-Rust LZO1X-999 decoder
//!
//! This is a faithful Rust port of the LZO1X decompression algorithm
//! as documented by the LZO reference implementation
//! (<http://www.oberhumer.com/opensource/lzo/>).

#![forbid(unsafe_code)]

/// Decompress an LZO stream. Returns `None` on any decode error.
pub fn decompress(input: &[u8]) -> Option<Vec<u8>> {
    let mut s = State {
        input,
        ip: 0,
        out: Vec::with_capacity(input.len() * 4),
    };
    s.run().then_some(s.out)
}

struct State<'a> {
    input: &'a [u8],
    ip: usize,
    out: Vec<u8>,
}

impl<'a> State<'a> {
    fn run(&mut self) -> bool {
        if self.ip >= self.input.len() {
            return false;
        }
        let first = self.input[self.ip];
        self.ip += 1;

        if first > 17 {
            // Match with 2-byte offset.
            let t = ((first - 17) & 0x0F) as usize;
            if t == 0 {
                if self.extend_length(0).is_none() {
                    return false;
                }
            }
            let off = match self.read_u16() {
                Some(v) => v as usize,
                None => return false,
            };
            if off == 0 {
                return true;
            }
            let m_len = 2 + t;
            if !self.copy_match_at(off, m_len) {
                return false;
            }
        } else {
            // Literal run.
            let n = match self.extend_length(first as u32) {
                Some(v) => v as usize,
                None => return false,
            };
            if !self.copy_literals(n) {
                return false;
            }
        }

        loop {
            if self.ip >= self.input.len() {
                return true;
            }
            let tt = self.input[self.ip];
            self.ip += 1;

            if tt < 16 {
                // Short literal run + match.
                let t = if tt == 0 {
                    match self.extend_length(0) {
                        Some(v) => v as usize,
                        None => return false,
                    }
                } else {
                    (tt + 1) as usize
                };
                if !self.copy_literals(t) {
                    return false;
                }
                let off = match self.read_u16() {
                    Some(v) => v as usize,
                    None => return false,
                };
                if off == 0 {
                    return true;
                }
                let m_len = 2 + if tt >= 8 { 1 } else { 0 };
                if !self.copy_match_at(off, m_len) {
                    return false;
                }
            } else if tt < 32 {
                let t = ((tt - 17) & 0x0F) as usize;
                let off_hi = ((tt & 0xF0) >> 4) as usize;
                let off_lo = match self.read_u8() {
                    Some(v) => v as usize,
                    None => return false,
                };
                let off = (off_hi << 8) | off_lo;
                if off == 0 {
                    return true;
                }
                let m_len = 2 + t;
                if !self.copy_match_at(off, m_len) {
                    return false;
                }
            } else if tt < 64 {
                let t = ((tt - 32) & 0x1F) as usize;
                let off = match self.read_u16() {
                    Some(v) => v as usize,
                    None => return false,
                };
                if off == 0 {
                    return true;
                }
                let m_len = if t == 0 {
                    match self.extend_length(0) {
                        Some(v) => v as usize + 2,
                        None => return false,
                    }
                } else {
                    t + 2
                };
                if !self.copy_match_at(off, m_len) {
                    return false;
                }
            } else {
                let t = ((tt - 64) & 0x3F) as usize;
                let off = match self.read_u16() {
                    Some(v) => v as usize,
                    None => return false,
                };
                if off == 0 {
                    return true;
                }
                let m_len = if t == 0 {
                    match self.extend_length(0) {
                        Some(v) => v as usize + 2,
                        None => return false,
                    }
                } else {
                    t + 2
                };
                if !self.copy_match_at(off, m_len) {
                    return false;
                }
            }
        }
    }

    fn read_u8(&mut self) -> Option<u8> {
        if self.ip >= self.input.len() {
            return None;
        }
        let v = self.input[self.ip];
        self.ip += 1;
        Some(v)
    }

    fn read_u16(&mut self) -> Option<u16> {
        if self.ip + 2 > self.input.len() {
            return None;
        }
        let v = u16::from_le_bytes([self.input[self.ip], self.input[self.ip + 1]]);
        self.ip += 2;
        Some(v)
    }

    fn extend_length(&mut self, base: u32) -> Option<u32> {
        if base == 0 {
            let mut acc: u32 = 0;
            loop {
                let b = self.read_u8()?;
                if b != 0 {
                    acc = acc.checked_add(b as u32)?;
                    break;
                }
                acc = acc.checked_add(255)?;
            }
            Some(acc)
        } else {
            Some(base)
        }
    }

    fn copy_literals(&mut self, n: usize) -> bool {
        if self.ip + n > self.input.len() {
            return false;
        }
        self.out
            .extend_from_slice(&self.input[self.ip..self.ip + n]);
        self.ip += n;
        true
    }

    fn copy_match_at(&mut self, off: usize, m_len: usize) -> bool {
        if off == 0 || off > self.out.len() {
            return false;
        }
        let start = self.out.len() - off;
        for i in 0..m_len {
            let b = self.out[start + i];
            self.out.push(b);
        }
        true
    }
}
