// SPDX-License-Identifier: GPL-3.0-or-later
// Author: kelexine (https://github.com/kelexine)
// Rust port of marin-m/vmlinux-to-elf (https://github.com/marin-m/vmlinux-to-elf)
//
//! Kernel-database lookup (`extract_db_information` in the reference tool).
//!
//! Purely informational: looks the detected kernel version up in the bundled
//! database and logs where to read/download its source, which files matter for
//! the detected architecture, and a Debian build environment contemporary with
//! the release. It never influences symbol recovery or the produced ELF, and a
//! database problem is reported as a warning, never as a failure.

#![forbid(unsafe_code)]

use crate::version::KernelVersionInfo;
use v2e_db::{KernelDb, KernelRelevantFile};

/// Log everything the database knows about `version` / `elf_machine`.
pub fn log_db_information(db: &dyn KernelDb, version: &KernelVersionInfo, elf_machine: u16) {
    if let Err(e) = try_log_db_information(db, version, elf_machine) {
        log::warn!("[!] Kernel database lookup failed: {e}");
    }
}

fn try_log_db_information(
    db: &dyn KernelDb,
    version: &KernelVersionInfo,
    elf_machine: u16,
) -> Result<(), v2e_db::models::DbError> {
    let partial = format!("v{}.{}", version.major, version.minor);
    let full = match version.sublevel {
        Some(sub) => format!("{partial}.{sub}"),
        None => partial.clone(),
    };

    let Some(kernel) = db.find_kernel_version(&full, &partial)? else {
        return Ok(());
    };

    log::info!("[+] Kernel found in database");
    if let Some(url) = &kernel.browse_url {
        log::info!("[+]   Read kernel source: {url}");
    }
    log::info!("[+]   Download kernel: {}", kernel.download_url);
    log::info!(
        "[+]   Kernel release date: {}",
        kernel.release_date.format_iso()
    );

    if elf_machine != 0 {
        log::info!("[+]   Interesting files:");
        log_files(&db.find_relevant_files(&kernel.version_string, None)?);

        if let Some(machine) = db.find_emachine(i64::from(elf_machine))? {
            for link in db.find_arch_links(&machine.elf_machine_str)? {
                let arch = &link.architecture;
                let capacities: Vec<&str> = [
                    (arch.has_32bit_class, "32-bit"),
                    (arch.has_64bit_class, "64-bit"),
                    (arch.has_msb_class, "big-endian"),
                    (arch.has_lsb_class, "little-endian"),
                ]
                .into_iter()
                .filter_map(|(on, name)| on.then_some(name))
                .collect();
                log::info!(
                    "[+]   Architecture {} ({}) supports {}",
                    arch.architecture_code,
                    machine.elf_machine_str,
                    capacities.join(", ")
                );
                log_files(
                    &db.find_relevant_files(&kernel.version_string, Some(&arch.architecture_code))?,
                );
            }
        }
    }

    if let Some(debian) = db.find_debian_release(kernel.release_date)? {
        log::info!(
            "[+]   Suggested build environment: docker run -it {} (Debian {} \"{}\" released {})",
            debian.docker_archive_name,
            debian.debian_version_number,
            debian.debian_version_name,
            debian.debian_release_date.format_iso()
        );
    }
    Ok(())
}

fn log_files(files: &[KernelRelevantFile]) {
    for file in files {
        match &file.vcs_browser_url {
            Some(url) if !url.is_empty() => log::info!("[~]     - {}: {url}", file.file_name),
            _ => log::info!("[~]     - {}", file.file_name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use v2e_db::NoopKernelDb;

    fn version() -> KernelVersionInfo {
        KernelVersionInfo {
            version_string: "Linux version 4.19.127".into(),
            version_number: "4.19.127".into(),
            major: 4,
            minor: 19,
            sublevel: Some(127),
        }
    }

    #[test]
    fn noop_database_is_silent_and_never_fails() {
        log_db_information(&NoopKernelDb, &version(), 183);
    }
}
