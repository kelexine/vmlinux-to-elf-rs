// SPDX-License-Identifier: GPL-3.0-or-later

//! Domain models + `KernelDb` trait.
//!
//! Each struct corresponds to one peewee `Model` subclass. Field names are
//! preserved verbatim (modulo `snake_case`, which peewee already uses).
//!
//! The `KernelDb` trait abstracts the read-only queries used by:
//!
//! - `find_kernel_version(full, partial) -> Option<KernelVersion>`
//! - `find_emachine(elf_machine_int) -> Option<EmachineValue>`
//! - `find_arch_links(elf_machine_str) -> Vec<ArchitectureEmachineLink>`
//! - `find_relevant_files(release, architecture_code) -> Vec<KernelRelevantFile>`
//! - `find_debian_release(<=release_date) -> Option<DebianRelease>`
//!
//! Implementations:
//!
//! - `NoopKernelDb` — returns `None`/empty for everything.
//! - `RusqliteKernelDb` (feature `db`) — opens lazily, read-only, against
//!   the bundled `database.sqlite3`.

#![forbid(unsafe_code)]

use std::path::Path;

/// Mirror of `KernelVersion` peewee model.
#[derive(Clone, Debug, Default)]
pub struct KernelVersion {
    /// Git tag, e.g. `v6.1.162`.
    pub version_string: String,
    /// `git` or `tarball`.
    pub kernel_source: String,
    /// Browse URL (kernel.org).
    pub browse_url: Option<String>,
    /// Tarball download URL.
    pub download_url: String,
    /// Git commit SHA, when known.
    pub git_commit: Option<String>,
    /// Release date (`YYYY-MM-DD`).
    pub release_date: chrono_date::Date,
}

/// Mirror of `EMachineValue` peewee model.
#[derive(Clone, Debug, Default)]
pub struct EmachineValue {
    /// e.g. `EM_AARCH64`.
    pub elf_machine_str: String,
    /// e.g. `183`.
    pub elf_machine_int: i64,
}

/// Mirror of `KnownArchitecture` peewee model.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default)]
pub struct KnownArchitecture {
    /// e.g. `arm64`, `x86_64`.
    pub architecture_code: String,
    /// Whether a 32-bit ELF class is supported.
    pub has_32bit_class: bool,
    /// Whether a 64-bit ELF class is supported.
    pub has_64bit_class: bool,
    /// Whether a big-endian (MSB) ELF data encoding is supported.
    pub has_msb_class: bool,
    /// Whether a little-endian (LSB) ELF data encoding is supported.
    pub has_lsb_class: bool,
}

/// Mirror of `ArchitectureEMachineLink` peewee model.
#[derive(Clone, Debug)]
pub struct ArchitectureEmachineLink {
    /// Architecture code.
    pub architecture: KnownArchitecture,
    /// EM_* string.
    pub e_machine: EmachineValue,
}

/// Mirror of `KernelSupportedArch` peewee model.
#[derive(Clone, Debug)]
pub struct KernelSupportedArch {
    /// Kernel version string (FK to `KernelVersion`).
    pub release: String,
    /// Architecture supported by this release.
    pub architecture: KnownArchitecture,
}

/// Mirror of `KernelRelevantFile` peewee model.
#[derive(Clone, Debug, Default)]
pub struct KernelRelevantFile {
    /// Row id (auto-increment in `SQLite`).
    pub id: i64,
    /// Kernel version string (FK to `KernelVersion`).
    pub release: String,
    /// File name within the kernel source tree.
    pub file_name: String,
    /// Architecture code (NULL = applies to all arches).
    pub architecture_code: Option<String>,
    /// VCS browser URL pointing at the file in the kernel git tree.
    pub vcs_browser_url: Option<String>,
}

/// Mirror of `DebianRelease` peewee model.
#[derive(Clone, Debug, Default)]
pub struct DebianRelease {
    /// e.g. `bookworm`.
    pub docker_archive_name: String,
    /// e.g. `Debian 12`.
    pub debian_version_name: String,
    /// e.g. `12.0`.
    pub debian_version_number: String,
    /// Release date.
    pub debian_release_date: chrono_date::Date,
}

/// Trait abstracting the kernel-version database. Every method returns
/// `Option` or `Vec` and never panics on missing data.
///
/// All methods may return [`DbError`] when the underlying store is
/// unavailable or corrupt; callers should propagate the error.
pub trait KernelDb: std::fmt::Debug + Send + Sync {
    /// `KernelVersion.select().where(version_string == full)` then
    /// `.where(version_string == partial)`.
    ///
    /// # Errors
    /// Returns [`DbError`] when the underlying store is unavailable or corrupt.
    fn find_kernel_version(
        &self,
        full: &str,
        partial: &str,
    ) -> Result<Option<KernelVersion>, DbError>;

    /// `EMachineValue.select().where(elf_machine_int == em)`.
    ///
    /// # Errors
    /// Returns [`DbError`] when the underlying store is unavailable or corrupt.
    fn find_emachine(&self, em: i64) -> Result<Option<EmachineValue>, DbError>;

    /// All `ArchitectureEMachineLink` rows whose `e_machine` matches
    /// `em_str` (the `elf_machine_str` column).
    ///
    /// # Errors
    /// Returns [`DbError`] when the underlying store is unavailable or corrupt.
    fn find_arch_links(&self, em_str: &str) -> Result<Vec<ArchitectureEmachineLink>, DbError>;

    /// All `KernelRelevantFile` rows for `release` whose
    /// `architecture_code` matches `arch_code` (or is NULL when `None`).
    ///
    /// # Errors
    /// Returns [`DbError`] when the underlying store is unavailable or corrupt.
    fn find_relevant_files(
        &self,
        release: &str,
        arch_code: Option<&str>,
    ) -> Result<Vec<KernelRelevantFile>, DbError>;

    /// `DebianRelease.select().where(date <= release_date).order_by(date.desc())`.
    ///
    /// # Errors
    /// Returns [`DbError`] when the underlying store is unavailable or corrupt.
    fn find_debian_release(
        &self,
        release_date: chrono_date::Date,
    ) -> Result<Option<DebianRelease>, DbError>;
}

/// No-op implementation used when the `db` feature is disabled or the
/// database file is absent. All queries return empty/`None`.
#[derive(Copy, Clone, Debug, Default)]
pub struct NoopKernelDb;

impl KernelDb for NoopKernelDb {
    fn find_kernel_version(
        &self,
        _full: &str,
        _partial: &str,
    ) -> Result<Option<KernelVersion>, DbError> {
        Ok(None)
    }
    fn find_emachine(&self, _em: i64) -> Result<Option<EmachineValue>, DbError> {
        Ok(None)
    }
    fn find_arch_links(&self, _em_str: &str) -> Result<Vec<ArchitectureEmachineLink>, DbError> {
        Ok(Vec::new())
    }
    fn find_relevant_files(
        &self,
        _release: &str,
        _arch_code: Option<&str>,
    ) -> Result<Vec<KernelRelevantFile>, DbError> {
        Ok(Vec::new())
    }
    fn find_debian_release(
        &self,
        _release_date: chrono_date::Date,
    ) -> Result<Option<DebianRelease>, DbError> {
        Ok(None)
    }
}

/// Error type for DB operations.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// `rusqlite` error. Only constructible when the `db` feature is enabled.
    #[cfg(feature = "db")]
    #[error("rusqlite error: {0}")]
    Rusqlite(#[from] rusqlite::Error),
    /// Database file not found at the expected path.
    #[error("database file not found: {}", .0.display())]
    NotFound(std::path::PathBuf),
    /// Date parsing failure.
    #[error("date parse error: {0}")]
    Date(String),
    /// The connection lock was poisoned by a panic in another thread.
    #[error("database connection lock poisoned")]
    Locked,
    /// Failure while unpacking the embedded database.
    #[error("could not unpack the embedded database: {0}")]
    Extract(String),
}

/// Lightweight date wrapper. We use our own to avoid pulling in `chrono`
/// for what is essentially `YYYY-MM-DD` parsing + comparison.
pub mod chrono_date {
    use std::cmp::Ordering;
    use std::fmt;

    /// Calendar date (year, month, day).
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct Date {
        /// Year, e.g. `2026`.
        pub year: i32,
        /// Month `1..=12`.
        pub month: u8,
        /// Day `1..=31`.
        pub day: u8,
    }

    impl Date {
        /// Construct a new date. Does not validate the day-of-month.
        #[must_use]
        pub const fn new(year: i32, month: u8, day: u8) -> Self {
            Self { year, month, day }
        }

        /// Parse `YYYY-MM-DD`, optionally followed by a time and UTC offset
        /// (`2018-10-22 07:37:37+01:00` or `…T…`), which is how the
        /// `kernel_version.release_date` column is stored. The calendar date
        /// is taken as written, i.e. in the stored offset, like the reference
        /// tool does. Returns `None` on malformed input.
        #[must_use]
        pub fn parse_iso(s: &str) -> Option<Self> {
            let s = match s.as_bytes().get(10) {
                None => s,
                Some(b' ' | b'T') => s.get(..10)?,
                Some(_) => return None,
            };
            let mut parts = s.split('-');
            let year: i32 = parts.next()?.parse().ok()?;
            let month: u8 = parts.next()?.parse().ok()?;
            let day: u8 = parts.next()?.parse().ok()?;
            if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
                return None;
            }
            Some(Self { year, month, day })
        }

        /// Format as `YYYY-MM-DD`.
        #[must_use]
        pub fn format_iso(&self) -> String {
            format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
        }

        /// Compare two dates as `(year, month, day)` tuples.
        #[must_use]
        pub fn compare(&self, other: &Self) -> Ordering {
            (self.year, self.month, self.day).cmp(&(other.year, other.month, other.day))
        }
    }

    impl fmt::Display for Date {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.format_iso())
        }
    }

    impl PartialOrd for Date {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(std::cmp::Ord::cmp(self, other))
        }
    }

    impl Ord for Date {
        fn cmp(&self, other: &Self) -> Ordering {
            self.compare(other)
        }
    }
}
