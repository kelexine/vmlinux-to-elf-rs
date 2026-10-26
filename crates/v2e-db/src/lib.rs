// SPDX-License-Identifier: GPL-3.0-or-later

//! `v2e-db` — optional kernel-version database access.
//!
//! The DB contributes **zero bytes** to the output ELF — it is purely
//! informational logging that suggests a Debian build environment matching
//! the kernel's release date.
//!
//! Two implementations:
//!
//! - `RusqliteKernelDb` (feature `db`, default): opens the bundled 33 MB
//!   `database.sqlite3` lazily via `rusqlite::Connection::open_with_flags`
//!   with `SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX`.
//! - `NoopKernelDb`: returns `Ok(None)` for every query. Used when the
//!   `db` feature is disabled, or when the DB file is missing.
//!
//! Path resolution order:
//!   1. `--db-path <FILE>` CLI flag (highest priority)
//!   2. `V2E_DB_PATH` environment variable
//!   3. `<exe_dir>/database.sqlite3` (bundled alongside the binary)
//!   4. `./database.sqlite3` (current working directory)
//!   5. Absent — `NoopKernelDb` is used silently.

#![forbid(unsafe_code)]
#![allow(missing_docs)]

#[cfg(feature = "db")]
pub mod rusqlite_impl;

#[cfg(feature = "db")]
pub use rusqlite_impl::RusqliteKernelDb;

pub mod models;
pub use models::{
    ArchitectureEmachineLink, DebianRelease, EmachineValue, KernelDb, KernelRelevantFile,
    KernelSupportedArch, KernelVersion, KnownArchitecture, NoopKernelDb,
};

pub use chrono_date::Date;
pub use models::chrono_date;
