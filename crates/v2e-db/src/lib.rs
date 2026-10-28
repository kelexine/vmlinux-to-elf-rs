// SPDX-License-Identifier: GPL-3.0-or-later

//! `v2e-db` — optional kernel-version database access.
//!
//! The DB contributes **zero bytes** to the output ELF — it is purely
//! informational logging that suggests a Debian build environment matching
//! the kernel's release date.
//!
//! Two implementations:
//!
//! - `RusqliteKernelDb` (feature `db`, default): opens `database.sqlite3`
//!   lazily and read-only (`SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX`).
//! - `NoopKernelDb`: returns `Ok(None)` for every query. Used when the `db`
//!   feature is disabled or no database could be located.
//!
//! Where the file comes from is described in [`locate`]: explicit path,
//! `V2E_DB_PATH`, next to the executable, share/data directories, the current
//! directory, and finally (feature `embedded`, default) a 1.8 MB compressed
//! copy compiled into the binary that is unpacked once on first use.
//! [`open_default`] ties it together.

#![forbid(unsafe_code)]
#![allow(missing_docs)]

#[cfg(feature = "db")]
pub mod rusqlite_impl;

#[cfg(feature = "db")]
pub use rusqlite_impl::RusqliteKernelDb;

pub mod locate;
pub use locate::{resolve_db_path, user_data_dir, DB_FILE_NAME, ENV_DB_PATH};

pub mod models;
pub use models::{
    ArchitectureEmachineLink, DebianRelease, EmachineValue, KernelDb, KernelRelevantFile,
    KernelSupportedArch, KernelVersion, KnownArchitecture, NoopKernelDb,
};

pub use chrono_date::Date;
pub use models::chrono_date;

/// Open the kernel database using the standard lookup chain.
///
/// Never opens the file eagerly. When nothing can be located the returned
/// handle is a [`NoopKernelDb`], because the database only feeds log output.
///
/// # Errors
/// [`DbError`] only when `explicit` was given but does not exist.
pub fn open_default(
    explicit: Option<&std::path::Path>,
) -> Result<std::sync::Arc<dyn KernelDb>, models::DbError> {
    #[cfg(feature = "db")]
    {
        if let Some(path) = resolve_db_path(explicit)? {
            log::debug!("[+] Kernel database: {}", path.display());
            return Ok(std::sync::Arc::new(RusqliteKernelDb::new(path)));
        }
    }
    #[cfg(not(feature = "db"))]
    {
        if let Some(p) = explicit {
            return Err(models::DbError::NotFound(p.to_path_buf()));
        }
    }
    log::debug!("[~] No kernel database available; skipping kernel lookup");
    Ok(std::sync::Arc::new(NoopKernelDb))
}
