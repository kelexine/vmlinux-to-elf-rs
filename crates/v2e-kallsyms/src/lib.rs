// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `v2e-kallsyms`
//!
//! Locates the embedded `kallsyms` symbol table inside a raw kernel blob
//! (or already-relocated ELF) and decodes it into a list of named symbols
//! with virtual addresses, types, and binding flags.
//!
//!
//! Module layout:
//!
//! ```text
//! v2e-kallsyms/
//! └── src/
//!     ├── lib.rs               // crate root, KallsymsFinder orchestrator
//!     ├── error.rs             // KallsymsError (thiserror)
//!     ├── cursor.rs            // bounds-checked read cursor over &[u8]
//!     ├── db_info.rs           // kernel-database lookup (informational logging)
//!     ├── elf_preprocess.rs    // ELF-input pre-pass: apply .rela.dyn before detection
//!     ├── symbol.rs            // KallsymsSymbol + KallsymsSymbolType
//!     ├── version.rs           // find_linux_kernel_version regex
//!     ├── rela.rs              // ARM64 R_AARCH64_RELATIVE / R_AARCH64_ABS64 scan + apply
//!     └── detect/
//!         ├── mod.rs
//!         ├── token_table.rs    // H1
//!         ├── token_index.rs    // H2 (also sets endianness!)
//!         ├── markers.rs        // H8 + OpenWRT uncompressed variant
//!         ├── names.rs          // H3, H9, OpenWRT uncompressed
//!         ├── num_syms.rs       // H3 DP backward count
//!         └── addresses.rs     // H4 3-mode heuristic (base_relative / pc_relative / absolute)
//! ```

#![forbid(unsafe_code)]
#![allow(missing_docs)]
#![warn(missing_docs)]

pub mod cursor;
pub mod db_info;
pub mod elf_preprocess;
pub mod error;
pub mod rela;
pub mod symbol;
pub mod version;

pub mod detect;

pub use error::{KallsymsError, KallsymsNotFoundException};
pub use symbol::{KallsymsSymbol, KallsymsSymbolType};

mod finder;
pub use finder::{KallsymsFinder, KallsymsFinderConfig};
