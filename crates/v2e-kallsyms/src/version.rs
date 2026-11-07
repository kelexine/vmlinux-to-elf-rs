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
    // `(?-u)`: byte semantics, as in the reference's `re` on `bytes`. Without it
    // `\d` also matches non-ASCII Unicode digits, and the engine cannot use the
    // fast literal-prefix search.
    let re = Regex::new(r"(?-u)Linux version (\d+\.[\d.]*\d)[ -~]+")
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

#[cfg(test)]
mod tests {
    use super::*;

    fn image(banner: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 64];
        v.extend_from_slice(banner);
        v.extend_from_slice(&[0u8; 64]);
        v
    }

    #[test]
    fn parses_a_typical_banner() {
        let img = image(b"Linux version 4.19.127-g1234 (user@host) (gcc 11.2) #1 SMP Tue Jan 1");
        let v = find_linux_kernel_version(&img).unwrap();
        assert_eq!((v.major, v.minor, v.sublevel), (4, 19, Some(127)));
        assert_eq!(v.version_number, "4.19.127");
        assert!(v.version_string.starts_with("Linux version 4.19.127-g1234"));
    }

    #[test]
    fn two_component_versions_have_no_sublevel() {
        let v = find_linux_kernel_version(&image(b"Linux version 6.8 (x@y) #1")).unwrap();
        assert_eq!((v.major, v.minor, v.sublevel), (6, 8, None));
    }

    #[test]
    fn first_banner_in_the_image_wins() {
        let mut img = image(b"Linux version 5.4.0 (a@b) #1");
        img.extend_from_slice(b"\0Linux version 9.9.9 (c@d) #2\0");
        assert_eq!(
            find_linux_kernel_version(&img).unwrap().version_number,
            "5.4.0"
        );
    }

    #[test]
    fn non_ascii_digits_do_not_count() {
        // Arabic-indic digits are Unicode digits but not ASCII digits; the
        // reference's byte regex would not match them either.
        let img = image("Linux version ١٢.٣ (a@b) #1".as_bytes());
        assert!(find_linux_kernel_version(&img).is_err());
    }

    #[test]
    fn missing_or_garbage_input_is_an_error() {
        assert!(find_linux_kernel_version(&[]).is_err());
        assert!(find_linux_kernel_version(b"Linux version ").is_err());
        assert!(find_linux_kernel_version(&[0xFF; 4096]).is_err());
    }
}
