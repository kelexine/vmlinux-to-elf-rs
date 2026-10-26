// SPDX-License-Identifier: GPL-3.0-or-later

//! Logging setup for the v2e CLI binaries.

#![forbid(unsafe_code)]

use std::io::Write;
use std::sync::OnceLock;

/// Initialize the global logger. Idempotent.
///
/// # Errors
/// Never returns an error; if the underlying logger fails to install,
/// the function silently continues.
pub fn init() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .format(|buf, record| writeln!(buf, "{}", record.args()))
            .filter_level(log::LevelFilter::Info)
            .write_style(env_logger::WriteStyle::Auto)
            .try_init();
    });
}

/// Print a `[+]` info line to stderr.
#[macro_export]
macro_rules! info_plus {
    ($($arg:tt)*) => { log::info!("[+] {}", format_args!($($arg)*)) };
}

/// Print a `[!]` warning line to stderr.
#[macro_export]
macro_rules! warn_bang {
    ($($arg:tt)*) => { log::warn!("[!] {}", format_args!($($arg)*)) };
}

/// Print a `[~]` info line to stderr.
#[macro_export]
macro_rules! info_tilde {
    ($($arg:tt)*) => { log::info!("[~] {}", format_args!($($arg)*)) };
}
