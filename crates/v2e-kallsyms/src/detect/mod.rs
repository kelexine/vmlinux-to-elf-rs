// SPDX-License-Identifier: GPL-3.0-or-later
//
//! kallsyms detection steps.

#![forbid(unsafe_code)]

pub mod addresses;
pub mod markers;
pub mod names;
pub mod num_syms;
pub mod token_index;
pub mod token_table;

pub use addresses::AddressesOrOffsets;
pub use markers::MarkersResult;
pub use names::NamesResult;
pub use num_syms::NumSymsResult;
pub use token_index::TokenIndexResult;
pub use token_table::TokenTableResult;
