// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Boot-image unpackers — Android boot.img, uImage, Qualcomm UNCOMPRESSED_IMG.

#![forbid(unsafe_code)]

pub mod android;
pub mod qualcomm;
pub mod uimage;

pub use android::AndroidBootImage;
pub use qualcomm::QualcommUncompressedImg;
pub use uimage::UImageHeader;
