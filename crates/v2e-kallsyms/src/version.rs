// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `find_linux_kernel_version` — faithful port of the regex match in
//! `kallsyms.py`.

#![forbid(unsafe_code)]

use crate::error::KallsymsError;
use regex::bytes::Regex;

/// Result of `find_linux_kernel_version`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelVersionInfo {
    /// Full version string (`Linux version X.Y.Z (...)`).
    pub version_string: String,
    /// Just the dotted version number (`X.Y.Z` or `X.Y`).
    pub version_number: String,
    /// Major (e.g. `6` for `6.1.162`).
    pub major: u32,
    /// Minor (e.g. `1` for `6.1.162`).
    pub minor: u32,
    /// Sublevel (e.g. `162` for `6.1.162`); `None` if the version string
    /// only had two components (e.g. `5.4`).
    pub sublevel: Option<u32>,
}

/// Find the embedded `Linux version X.Y.Z (...)` string in a raw kernel image.
///
/// # Errors
/// Returns [`KallsymsError::NoVersionString`] if no match is found.
pub fn find_linux_kernel_version(kernel_img: &[u8]) -> Result<KernelVersionInfo, KallsymsError> {
    let re = Regex::new(r"Linux version (\d+\.[\d.]*\d)[ -~]+")
        .map_err(|_| KallsymsError::NoVersionString)?;
    let caps = re
        .captures(kernel_img)
        .ok_or(KallsymsError::NoVersionString)?;
    let full_match = caps.get(0).map(|m| m.as_bytes()).unwrap_or(&[]);
    let version_number_bytes = caps.get(1).map(|m| m.as_bytes()).unwrap_or(&[]);

    let version_string = String::from_utf8_lossy(full_match).into_owned();
    let version_number = String::from_utf8_lossy(version_number_bytes).into_owned();

    let parts: Vec<&str> = version_number.split('.').collect();
    if parts.len() < 2 {
        return Err(KallsymsError::NoVersionString);
    }
    let major = parts[0]
        .parse::<u32>()
        .map_err(|_| KallsymsError::NoVersionString)?;
    let minor = parts[1]
        .parse::<u32>()
        .map_err(|_| KallsymsError::NoVersionString)?;
    let sublevel = if parts.len() >= 3 {
        parts[2].parse::<u32>().ok()
    } else {
        None
    };

    log::info!("[+] Version string: {}", version_string);

    Ok(KernelVersionInfo {
        version_string,
        version_number,
        major,
        minor,
        sublevel,
    })
}
