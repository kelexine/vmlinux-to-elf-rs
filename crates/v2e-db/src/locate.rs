// SPDX-License-Identifier: GPL-3.0-or-later
// Author: kelexine (https://github.com/kelexine)
// Rust port of marin-m/vmlinux-to-elf (https://github.com/marin-m/vmlinux-to-elf)
//
//! Locating (and, if needed, materializing) the kernel database.
//!
//! Lookup order, first existing file wins:
//!
//! 1. the explicit path passed by the caller (`--db-path`); if it is given but
//!    missing that is an error, never a silent fallback
//! 2. the `V2E_DB_PATH` environment variable
//! 3. `<exe_dir>/database.sqlite3`
//! 4. `<exe_dir>/../share/vmlinux-to-elf/database.sqlite3` (prefix installs)
//! 5. `<user data dir>/vmlinux-to-elf/database.sqlite3`
//! 6. `/usr/local/share/vmlinux-to-elf/…` then `/usr/share/vmlinux-to-elf/…`
//! 7. `./database.sqlite3`
//! 8. with the `embedded` feature: the copy compiled into the binary is
//!    extracted once to the user data directory and reused afterwards
//!
//! Step 8 is what makes `cargo install --git …` and local `cargo build`
//! self-contained: no post-install hook is needed because the binary carries a
//! 1.8 MB xz-compressed database and unpacks it on first use.

#![forbid(unsafe_code)]

use crate::models::DbError;
use std::path::{Path, PathBuf};

/// File name looked up in every directory of the search chain.
pub const DB_FILE_NAME: &str = "database.sqlite3";
/// Directory name used under share/data roots.
pub const APP_DIR: &str = "vmlinux-to-elf";
/// Environment variable overriding the database location.
pub const ENV_DB_PATH: &str = "V2E_DB_PATH";

/// Compressed database compiled into the binary.
#[cfg(feature = "embedded")]
static EMBEDDED_XZ: &[u8] = include_bytes!("../data/kernel_db.sqlite3.xz");

/// Per-user data directory (`$XDG_DATA_HOME`, `~/.local/share`, or the
/// platform equivalent), with the application sub-directory appended.
#[must_use]
pub fn user_data_dir() -> Option<PathBuf> {
    let base = if let Some(x) = non_empty_env("XDG_DATA_HOME") {
        PathBuf::from(x)
    } else if cfg!(windows) {
        PathBuf::from(non_empty_env("LOCALAPPDATA")?)
    } else if cfg!(target_os = "macos") {
        PathBuf::from(non_empty_env("HOME")?).join("Library/Application Support")
    } else {
        PathBuf::from(non_empty_env("HOME")?).join(".local/share")
    };
    Some(base.join(APP_DIR))
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Existing-file candidates in lookup order (steps 2–7 above).
#[must_use]
pub fn candidate_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(p) = non_empty_env(ENV_DB_PATH) {
        out.push(PathBuf::from(p));
    }
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
    {
        out.push(dir.join(DB_FILE_NAME));
        out.push(dir.join("../share").join(APP_DIR).join(DB_FILE_NAME));
    }
    if let Some(dir) = user_data_dir() {
        out.push(dir.join(DB_FILE_NAME));
    }
    out.push(
        Path::new("/usr/local/share")
            .join(APP_DIR)
            .join(DB_FILE_NAME),
    );
    out.push(Path::new("/usr/share").join(APP_DIR).join(DB_FILE_NAME));
    out.push(PathBuf::from(DB_FILE_NAME));
    out
}

/// Resolve the database file.
///
/// * `Ok(Some(path))` — a usable file was found (or extracted).
/// * `Ok(None)` — nothing found and nothing could be extracted; callers fall
///   back to [`crate::NoopKernelDb`] (the database only feeds log output).
///
/// # Errors
/// [`DbError::NotFound`] when `explicit` was provided but is not a file.
pub fn resolve_db_path(explicit: Option<&Path>) -> Result<Option<PathBuf>, DbError> {
    if let Some(p) = explicit {
        return if p.is_file() {
            Ok(Some(p.to_path_buf()))
        } else {
            Err(DbError::NotFound(p.to_path_buf()))
        };
    }
    if let Some(p) = non_empty_env(ENV_DB_PATH) {
        if !Path::new(&p).is_file() {
            log::warn!("[!] {ENV_DB_PATH} points to {p}, which is not a file; ignoring");
        }
    }
    if let Some(found) = candidate_paths().into_iter().find(|p| p.is_file()) {
        return Ok(Some(found));
    }
    #[cfg(feature = "embedded")]
    {
        match ensure_embedded_db() {
            Ok(p) => return Ok(Some(p)),
            Err(e) => log::warn!("[!] Could not unpack the embedded kernel database: {e}"),
        }
    }
    Ok(None)
}

/// File name of the extracted embedded copy; tagged with the crate version so
/// an upgrade never keeps serving a stale database.
#[cfg(feature = "embedded")]
fn extracted_name() -> String {
    format!("database-{}.sqlite3", env!("CARGO_PKG_VERSION"))
}

/// Extract the compiled-in database (once) and return its path.
///
/// The target is `<user data dir>/database-<version>.sqlite3`, falling back to
/// the system temp directory when no data directory is available or writable.
/// Extraction is atomic (temp file + rename), so concurrent first runs cannot
/// observe a half-written database.
///
/// # Errors
/// [`DbError::Extract`] on decompression or I/O failure.
#[cfg(feature = "embedded")]
pub fn ensure_embedded_db() -> Result<PathBuf, DbError> {
    let mut last_err: Option<DbError> = None;
    let dirs = user_data_dir()
        .into_iter()
        .chain(std::iter::once(std::env::temp_dir().join(APP_DIR)));
    for dir in dirs {
        let target = dir.join(extracted_name());
        if target.is_file() {
            return Ok(target);
        }
        match extract_to(&dir, &target) {
            Ok(()) => {
                log::info!(
                    "[+] Unpacked the embedded kernel database to {}",
                    target.display()
                );
                return Ok(target);
            },
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| DbError::Extract("no writable directory".into())))
}

#[cfg(feature = "embedded")]
fn extract_to(dir: &Path, target: &Path) -> Result<(), DbError> {
    use std::io::{Read, Write};

    let io_err = |what: &str, e: std::io::Error| DbError::Extract(format!("{what}: {e}"));

    std::fs::create_dir_all(dir).map_err(|e| io_err("create directory", e))?;
    let tmp = dir.join(format!(".{}.{}.tmp", extracted_name(), std::process::id()));

    let result = (|| {
        let mut decoder = xz2::read::XzDecoder::new(EMBEDDED_XZ);
        let mut file = std::fs::File::create(&tmp).map_err(|e| io_err("create temp file", e))?;
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let n = decoder
                .read(&mut buf)
                .map_err(|e| DbError::Extract(format!("xz decode: {e}")))?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])
                .map_err(|e| io_err("write database", e))?;
        }
        file.flush().map_err(|e| io_err("flush database", e))?;
        drop(file);
        std::fs::rename(&tmp, target).map_err(|e| io_err("install database", e))
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    // Another process may have installed the file first; that is success too.
    if target.is_file() {
        let _ = std::fs::remove_file(&tmp);
        return Ok(());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_missing_path_is_an_error() {
        let err = resolve_db_path(Some(Path::new("/definitely/not/here.sqlite3"))).unwrap_err();
        assert!(matches!(err, DbError::NotFound(_)));
    }

    #[test]
    fn explicit_existing_path_wins() {
        let dir = std::env::temp_dir().join(format!("v2e-locate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("x.sqlite3");
        std::fs::write(&f, b"x").unwrap();
        assert_eq!(resolve_db_path(Some(&f)).unwrap(), Some(f.clone()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Extract the embedded DB into a unique temp dir and open it.
    #[cfg(all(feature = "embedded", feature = "db"))]
    fn real_db() -> (crate::RusqliteKernelDb, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "v2e-realdb-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let target = dir.join("database.sqlite3");
        extract_to(&dir, &target).expect("extract embedded database");
        (crate::RusqliteKernelDb::new(target), dir)
    }

    #[cfg(all(feature = "embedded", feature = "db"))]
    #[test]
    fn embedded_database_extracts_to_the_exact_upstream_size() {
        let (_db, dir) = real_db();
        let len = std::fs::metadata(dir.join("database.sqlite3"))
            .unwrap()
            .len();
        assert_eq!(
            len, 34_234_368,
            "decompressed size must match the upstream file"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(all(feature = "embedded", feature = "db"))]
    #[test]
    fn real_database_answers_the_queries_the_reference_makes() {
        use crate::KernelDb;
        use crate::models::chrono_date::Date;
        let (db, dir) = real_db();

        // 4.19.127 is not in the table; the partial v4.19 row must be used and its
        // DATETIME-with-offset release date must parse (this used to fail silently).
        let kv = db
            .find_kernel_version("v4.19.127", "v4.19")
            .unwrap()
            .expect("v4.19 present");
        assert_eq!(kv.version_string, "v4.19");
        assert_eq!(kv.release_date, Date::parse_iso("2018-10-22").unwrap());
        assert!(kv.download_url.ends_with("v4.19.tar.gz"));

        assert!(
            db.find_kernel_version("v99.1.1", "v99.1")
                .unwrap()
                .is_none()
        );

        let em = db.find_emachine(183).unwrap().expect("EM_AARCH64");
        assert_eq!(em.elf_machine_str, "EM_AARCH64");
        let links = db.find_arch_links("EM_AARCH64").unwrap();
        assert!(
            links
                .iter()
                .any(|l| l.architecture.architecture_code == "arm64"
                    && l.architecture.has_64bit_class)
        );

        let files = db.find_relevant_files("v4.19", None).unwrap();
        assert!(files.iter().any(|f| f.file_name == "kernel/kallsyms.c"));
        let arm = db.find_relevant_files("v4.19", Some("arm64")).unwrap();
        assert!(arm.iter().any(|f| f.file_name.contains("booting")));

        let deb = db
            .find_debian_release(kv.release_date)
            .unwrap()
            .expect("a Debian release predates 2018-10-22");
        assert_eq!(deb.docker_archive_name, "debian/eol:stretch");

        // Before any Debian release in the table there is simply no suggestion.
        assert!(
            db.find_debian_release(Date::parse_iso("1990-01-01").unwrap())
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn datetime_with_offset_parses_to_its_written_calendar_date() {
        use crate::models::chrono_date::Date;
        let plain = Date::parse_iso("2018-10-22").unwrap();
        assert_eq!(Date::parse_iso("2018-10-22 07:37:37+01:00"), Some(plain));
        assert_eq!(Date::parse_iso("2018-10-22T07:37:37-07:00"), Some(plain));
        assert_eq!(Date::parse_iso("2018-10-22X07"), None);
        assert_eq!(Date::parse_iso("garbage-in"), None);
        assert_eq!(Date::parse_iso(""), None);
        assert_eq!(Date::parse_iso("2018-13-40"), None);
    }

    #[test]
    fn candidate_chain_contains_every_documented_location() {
        let joined = candidate_paths()
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(joined.contains("/usr/share/vmlinux-to-elf/database.sqlite3"));
        assert!(joined.contains("/usr/local/share/vmlinux-to-elf/database.sqlite3"));
        assert!(joined.contains("../share/vmlinux-to-elf/database.sqlite3"));
        assert!(joined.ends_with("database.sqlite3"));
    }
}
