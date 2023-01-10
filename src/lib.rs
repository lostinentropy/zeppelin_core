//! zeppelin_core is a library that implements a stream cipher based on
//! [Balloon hashing](https://en.wikipedia.org/wiki/Balloon_hashing).
//!
//! ## ⚠️ WARNING: Do not use ⚠️
//! This project is just for fun.
//! Neither the design nor the implementation of this library have been
//! independently evaluated.
//!
//! ## Cryptographic Features
//! - authenticated encryption
//! - passwords are **always** salted
//! - arbitrary scalable time and space complexity
//! - it's an [all-or-nothing transform](https://en.wikipedia.org/wiki/All-or-nothing_transform)
//!
//! ## Non-cryptographic features
//! - flexible container format that can be extended
//! - can be used on anything that implements the `Read` and `Seek` traits
//!
//! ## Examples
//! This example example shows how to use the high-level API based on the `Read` and `Write` traits.
//! ```
//! # use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
//! # use zeppelin_core::{container, progress::Progress, cipher::{self, CryptSettings}};
//! // High level functions are based on the `read` and `write` traits
//! // so we will convert our message to a cursor
//! let data: Vec<u8> = b"Secret message".to_vec();
//! let mut source = Cursor::new(data);
//!
//! let mut tmp = Cursor::new(Vec::<u8>::new());
//!
//! container::create_container(
//!     &mut source,
//!     &mut tmp,
//!     "Secret password",
//!     CryptSettings::default_for_testing(),
//!     None,
//! ).expect("Failed to create encrypted container!");
//! tmp.rewind().unwrap();
//!
//! let mut res = Cursor::new(Vec::<u8>::new());
//!
//! container::read_container(&mut tmp, &mut res, "Secret password", None).unwrap();
//!
//! assert_eq!(source, res)
//! ```
//!
//! The strength of the encryption is determined by the provided `CryptSettings`
//! object.

pub mod cipher;
// mod files;
pub mod container;
pub mod hash;
pub mod progress;

#[cfg(feature = "1password")]
pub mod op;
