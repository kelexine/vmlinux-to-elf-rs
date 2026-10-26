// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `RusqliteKernelDb` — lazy + read-only `rusqlite` implementation.

#![forbid(unsafe_code)]

use crate::models::{
    chrono_date::Date, ArchitectureEmachineLink, DbError, DebianRelease, EmachineValue, KernelDb,
    KernelRelevantFile, KernelVersion, KnownArchitecture,
};
use std::sync::OnceLock;

/// Lazily-opened, read-only SQLite connection.
pub struct RusqliteKernelDb {
    path: std::path::PathBuf,
    conn: OnceLock<rusqlite::Connection>,
}

impl RusqliteKernelDb {
    #[must_use]
    pub fn new(path: std::path::PathBuf) -> Self {
        Self {
            path,
            conn: OnceLock::new(),
        }
    }

    fn conn(&self) -> Result<&rusqlite::Connection, DbError> {
        if let Some(existing) = self.conn.get() {
            return Ok(existing);
        }
        let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_URI;
        let opened =
            rusqlite::Connection::open_with_flags(&self.path, flags).map_err(DbError::Rusqlite)?;
        let _ = self.conn.set(opened);
        Ok(self
            .conn
            .get()
            .expect("connection just set or already present"))
    }
}

impl KernelDb for RusqliteKernelDb {
    fn find_kernel_version(
        &self,
        full: &str,
        partial: &str,
    ) -> Result<Option<KernelVersion>, DbError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT version_string, kernel_source, browse_url, download_url, git_commit, release_date \
                 FROM kernel_version WHERE version_string = ? LIMIT 1",
            )
            .map_err(DbError::Rusqlite)?;
        let mut rows = stmt.query([full]).map_err(DbError::Rusqlite)?;
        if let Some(row) = rows.next().map_err(DbError::Rusqlite)? {
            return Ok(Some(row_to_kernel_version(row)));
        }
        // Fallback to partial.
        let mut stmt2 = conn
            .prepare(
                "SELECT version_string, kernel_source, browse_url, download_url, git_commit, release_date \
                 FROM kernel_version WHERE version_string = ? LIMIT 1",
            )
            .map_err(DbError::Rusqlite)?;
        let mut rows2 = stmt2.query([partial]).map_err(DbError::Rusqlite)?;
        if let Some(row) = rows2.next().map_err(DbError::Rusqlite)? {
            return Ok(Some(row_to_kernel_version(row)));
        }
        Ok(None)
    }

    fn find_emachine(&self, em: i64) -> Result<Option<EmachineValue>, DbError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT elf_machine_str, elf_machine_int FROM e_machine_value WHERE elf_machine_int = ? LIMIT 1")
            .map_err(DbError::Rusqlite)?;
        let mut rows = stmt.query([em]).map_err(DbError::Rusqlite)?;
        if let Some(row) = rows.next().map_err(DbError::Rusqlite)? {
            return Ok(Some(EmachineValue {
                elf_machine_str: row.get::<_, String>(0)?,
                elf_machine_int: row.get::<_, i64>(1)?,
            }));
        }
        Ok(None)
    }

    fn find_arch_links(&self, em_str: &str) -> Result<Vec<ArchitectureEmachineLink>, DbError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT a.architecture_code, a.has_32bit_class, a.has_64bit_class, a.has_msb_class, a.has_lsb_class, \
                 e.elf_machine_str, e.elf_machine_int \
                 FROM architecture_e_machine_link l \
                 JOIN known_architecture a ON a.architecture_code = l.architecture_id \
                 JOIN e_machine_value e ON e.elf_machine_str = l.e_machine_id \
                 WHERE l.e_machine_id = ?",
            )
            .map_err(DbError::Rusqlite)?;
        let rows = stmt
            .query_map([em_str], |row| {
                Ok(ArchitectureEmachineLink {
                    architecture: KnownArchitecture {
                        architecture_code: row.get(0)?,
                        has_32bit_class: row.get::<_, i64>(1)? != 0,
                        has_64bit_class: row.get::<_, i64>(2)? != 0,
                        has_msb_class: row.get::<_, i64>(3)? != 0,
                        has_lsb_class: row.get::<_, i64>(4)? != 0,
                    },
                    e_machine: EmachineValue {
                        elf_machine_str: row.get(5)?,
                        elf_machine_int: row.get(6)?,
                    },
                })
            })
            .map_err(DbError::Rusqlite)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(DbError::Rusqlite)?);
        }
        Ok(out)
    }

    fn find_relevant_files(
        &self,
        release: &str,
        arch_code: Option<&str>,
    ) -> Result<Vec<KernelRelevantFile>, DbError> {
        let conn = self.conn()?;
        let mut stmt = if arch_code.is_some() {
            conn.prepare(
                "SELECT id, release_id, file_name, architecture_code, vcs_browser_url \
                 FROM kernel_relevant_file WHERE release_id = ? AND architecture_code = ?",
            )
            .map_err(DbError::Rusqlite)?
        } else {
            conn.prepare(
                "SELECT id, release_id, file_name, architecture_code, vcs_browser_url \
                 FROM kernel_relevant_file WHERE release_id = ? AND architecture_code IS NULL",
            )
            .map_err(DbError::Rusqlite)?
        };
        let rows = if let Some(code) = arch_code {
            stmt.query_map([release, code], row_to_relevant_file)
                .map_err(DbError::Rusqlite)?
        } else {
            stmt.query_map([release], row_to_relevant_file)
                .map_err(DbError::Rusqlite)?
        };
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(DbError::Rusqlite)?);
        }
        Ok(out)
    }

    fn find_debian_release(&self, release_date: Date) -> Result<Option<DebianRelease>, DbError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT docker_archive_name, debian_version_name, debian_version_number, debian_release_date \
                 FROM debian_release WHERE debian_release_date <= ? \
                 ORDER BY debian_release_date DESC LIMIT 1",
            )
            .map_err(DbError::Rusqlite)?;
        let date_str = release_date.format_iso();
        let mut rows = stmt.query([date_str]).map_err(DbError::Rusqlite)?;
        if let Some(row) = rows.next().map_err(DbError::Rusqlite)? {
            let date_str: String = row.get(3)?;
            let date = Date::parse_iso(&date_str).ok_or(DbError::Date(date_str))?;
            return Ok(Some(DebianRelease {
                docker_archive_name: row.get(0)?,
                debian_version_name: row.get(1)?,
                debian_version_number: row.get(2)?,
                debian_release_date: date,
            }));
        }
        Ok(None)
    }
}

fn row_to_kernel_version(row: &rusqlite::Row<'_>) -> KernelVersion {
    let release_date_str: String = row.get(5).unwrap_or_default();
    let release_date = Date::parse_iso(&release_date_str).unwrap_or_default();
    KernelVersion {
        version_string: row.get(0).unwrap_or_default(),
        kernel_source: row.get(1).unwrap_or_default(),
        browse_url: row.get(2).ok(),
        download_url: row.get(3).unwrap_or_default(),
        git_commit: row.get(4).ok(),
        release_date,
    }
}

fn row_to_relevant_file(row: &rusqlite::Row<'_>) -> rusqlite::Result<KernelRelevantFile> {
    Ok(KernelRelevantFile {
        id: row.get(0)?,
        release: row.get(1)?,
        file_name: row.get(2)?,
        architecture_code: row.get(3)?,
        vcs_browser_url: row.get(4)?,
    })
}
