// SPDX-License-Identifier: GPL-3.0-or-later
// Author: kelexine (https://github.com/kelexine)
// Rust port of marin-m/vmlinux-to-elf (https://github.com/marin-m/vmlinux-to-elf)
//
//! Shared `--db-path` / `--no-db` handling for the binaries.

#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::Arc;
use v2e_db::KernelDb;

/// Build the database handle for a run.
///
/// * `no_db` — skip the kernel lookup entirely (`None`).
/// * `db_path` — use exactly this file; a missing file is an error.
/// * otherwise the standard lookup chain, including the embedded copy.
///
/// # Errors
/// A human-readable message when `db_path` was given but is not a file.
pub fn open_kernel_db(
    db_path: Option<&Path>,
    no_db: bool,
) -> Result<Option<Arc<dyn KernelDb>>, String> {
    if no_db {
        return Ok(None);
    }
    v2e_db::open_default(db_path)
        .map(Some)
        .map_err(|e| format!("{e}"))
}
