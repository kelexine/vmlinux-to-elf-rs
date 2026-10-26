// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Bounds-checked read cursor over `&[u8]`.
//!
//! Used by every kallsyms detection step so that no `unwrap` / indexing
//! is ever performed on untrusted input.

#![forbid(unsafe_code)]

use thiserror::Error;

/// Cursor error.
#[derive(Debug, Error)]
pub enum CursorError {
    /// Read attempted past the end of the buffer.
    #[error("read past end of buffer at offset {offset}, needed {needed} bytes, had {available}")]
    EndOfBuffer {
        /// Absolute offset of the read.
        offset: usize,
        /// Bytes the caller asked for.
        needed: usize,
        /// Bytes actually available.
        available: usize,
    },
}

/// Bounds-checked cursor over a borrowed byte slice.
#[derive(Copy, Clone, Debug)]
pub struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Construct a new cursor at position 0.
    #[must_use]
    #[inline]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Total length of the underlying slice.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the underlying slice is empty.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Current absolute position.
    #[must_use]
    #[inline]
    pub const fn pos(&self) -> usize {
        self.pos
    }

    /// Underlying byte slice (read-only).
    #[must_use]
    #[inline]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Seek to an absolute position.
    ///
    /// # Errors
    /// Returns `EndOfBuffer` if `pos > self.len()`.
    #[inline]
    pub fn seek(&mut self, pos: usize) -> Result<(), CursorError> {
        if pos > self.bytes.len() {
            return Err(CursorError::EndOfBuffer {
                offset: pos,
                needed: 0,
                available: self.bytes.len(),
            });
        }
        self.pos = pos;
        Ok(())
    }

    /// Get `n` bytes starting at the current position, advancing the cursor.
    ///
    /// # Errors
    /// Returns `EndOfBuffer` if fewer than `n` bytes remain.
    #[inline]
    pub fn read(&mut self, n: usize) -> Result<&'a [u8], CursorError> {
        let remaining = self.bytes.len().saturating_sub(self.pos);
        if n > remaining {
            return Err(CursorError::EndOfBuffer {
                offset: self.pos,
                needed: n,
                available: remaining,
            });
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Peek `n` bytes starting at the current position without advancing.
    ///
    /// # Errors
    /// Returns `EndOfBuffer` if fewer than `n` bytes remain.
    #[inline]
    pub fn peek(&self, n: usize) -> Result<&'a [u8], CursorError> {
        let remaining = self.bytes.len().saturating_sub(self.pos);
        if n > remaining {
            return Err(CursorError::EndOfBuffer {
                offset: self.pos,
                needed: n,
                available: remaining,
            });
        }
        Ok(&self.bytes[self.pos..self.pos + n])
    }

    /// Read a single byte at the current position, advancing the cursor by 1.
    ///
    /// # Errors
    /// Returns `EndOfBuffer` if no byte remains.
    #[inline]
    pub fn read_u8(&mut self) -> Result<u8, CursorError> {
        Ok(self.read(1)?[0])
    }

    /// Read a `u16` in the given endianness, advancing the cursor by 2.
    ///
    /// # Errors
    /// Returns `EndOfBuffer` if fewer than 2 bytes remain.
    #[inline]
    pub fn read_u16(&mut self, big_endian: bool) -> Result<u16, CursorError> {
        let b = self.read(2)?;
        Ok(if big_endian {
            u16::from_be_bytes([b[0], b[1]])
        } else {
            u16::from_le_bytes([b[0], b[1]])
        })
    }

    /// Read a `u32` in the given endianness, advancing the cursor by 4.
    ///
    /// # Errors
    /// Returns `EndOfBuffer` if fewer than 4 bytes remain.
    #[inline]
    pub fn read_u32(&mut self, big_endian: bool) -> Result<u32, CursorError> {
        let b = self.read(4)?;
        Ok(if big_endian {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        })
    }

    /// Read a `u64` in the given endianness, advancing the cursor by 8.
    ///
    /// # Errors
    /// Returns `EndOfBuffer` if fewer than 8 bytes remain.
    #[inline]
    pub fn read_u64(&mut self, big_endian: bool) -> Result<u64, CursorError> {
        let b = self.read(8)?;
        Ok(if big_endian {
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        } else {
            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        })
    }

    /// Read a signed `i32` in the given endianness.
    ///
    /// # Errors
    /// Returns `EndOfBuffer` if fewer than 4 bytes remain.
    #[inline]
    pub fn read_i32(&mut self, big_endian: bool) -> Result<i32, CursorError> {
        Ok(self.read_u32(big_endian)? as i32)
    }

    /// Read a signed `i64` in the given endianness.
    ///
    /// # Errors
    /// Returns `EndOfBuffer` if fewer than 8 bytes remain.
    #[inline]
    pub fn read_i64(&mut self, big_endian: bool) -> Result<i64, CursorError> {
        Ok(self.read_u64(big_endian)? as i64)
    }

    /// Slice view of the underlying bytes from `start..end` (no cursor move).
    ///
    /// # Errors
    /// Returns `EndOfBuffer` if the range exceeds the slice length.
    #[inline]
    pub fn slice(&self, start: usize, end: usize) -> Result<&'a [u8], CursorError> {
        if end > self.bytes.len() || start > end {
            return Err(CursorError::EndOfBuffer {
                offset: start,
                needed: end - start,
                available: self.bytes.len().saturating_sub(start),
            });
        }
        Ok(&self.bytes[start..end])
    }

    /// Byte at `offset` without advancing the cursor.
    ///
    /// # Errors
    /// Returns `EndOfBuffer` if `offset >= len`.
    #[inline]
    pub fn byte_at(&self, offset: usize) -> Result<u8, CursorError> {
        self.bytes
            .get(offset)
            .copied()
            .ok_or(CursorError::EndOfBuffer {
                offset,
                needed: 1,
                available: self.bytes.len().saturating_sub(offset),
            })
    }
}
