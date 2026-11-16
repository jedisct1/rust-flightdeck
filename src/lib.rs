//! FlightDeck, a fast keyed cipher built on Keccak, and the authenticated encryption that comes with it.
//!
//! There are three layers, each built on the one before:
//!
//! - [`OverwriteDuplex`] is a duplex cipher.
//!   It absorbs a block, and gives back up to a block of output.
//! - [`FlightDeck`] is a deck cipher.
//!   Same thing, with inputs and outputs of any length. Long ones are processed several blocks at a time.
//! - [`DeckBo`] is authenticated encryption for a session of messages.
//!   That's the one to use to protect data.
//!
//! Each layer comes in four instances.
//! [`TurboShake128`] and [`TurboShake256`] are the fast ones.
//! [`Shake128`] and [`Shake256`] use twice as many rounds.
//!
//! ```
//! # #[cfg(feature = "alloc")] {
//! use flightdeck::TurboShake128Bo;
//!
//! let key = [0x42; 16];
//!
//! // Messages are encrypted and decrypted in the same order. The tags here are 16 bytes long.
//! let mut sender = TurboShake128Bo::<16>::new(&key)?;
//! let first = sender.encrypt(b"associated data", b"first message");
//! let second = sender.encrypt(b"", b"second message");
//!
//! let mut receiver = TurboShake128Bo::<16>::new(&key)?;
//! assert_eq!(receiver.decrypt(b"associated data", &first)?, b"first message");
//! assert_eq!(receiver.decrypt(b"", &second)?, b"second message");
//! # }
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! # Features
//!
//! - `alloc` adds the functions that return a `Vec`.
//! - `std` is on by default. For now, all it does is turn `alloc` on.
//!
//! Without them, the crate is `no_std` and doesn't allocate.
//!
//! # Performance
//!
//! Several blocks are processed at once with vector instructions:
//!
//! - x86-64: SSE2, AVX2 or AVX-512, picked when the program runs.
//! - AArch64: NEON.
//! - WebAssembly: only when built with `-C target-feature=+simd128`.
//!
//! Targets built without vector instructions, as kernels often are, process one block at a time.

#![no_std]
#![warn(missing_docs)]
// The vector code is not used on targets without vectors.
#![cfg_attr(
    not(any(
        all(target_arch = "x86_64", target_feature = "sse2"),
        all(
            target_arch = "aarch64",
            target_endian = "little",
            target_feature = "neon"
        ),
        all(target_arch = "wasm32", target_feature = "simd128")
    )),
    allow(dead_code)
)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

mod batch;
mod bo;
mod deck;
mod duplex;
mod keccak;
mod simd;
#[cfg(test)]
mod tests;
mod trailer;
mod variant;

use core::fmt;

pub use bo::DeckBo;
pub use deck::FlightDeck;
pub use duplex::OverwriteDuplex;
pub use trailer::{DuplexTrailer, Trailer};
pub use variant::{Shake128, Shake256, TurboShake128, TurboShake256, Variant};

/// Duplex cipher based on TurboSHAKE128, with blocks of 160 bytes.
pub type TurboShake128Duplex = OverwriteDuplex<TurboShake128>;
/// Duplex cipher based on TurboSHAKE256, with blocks of 128 bytes.
pub type TurboShake256Duplex = OverwriteDuplex<TurboShake256>;
/// Duplex cipher based on SHAKE128, with blocks of 160 bytes.
pub type Shake128Duplex = OverwriteDuplex<Shake128>;
/// Duplex cipher based on SHAKE256, with blocks of 128 bytes.
pub type Shake256Duplex = OverwriteDuplex<Shake256>;

/// Deck cipher based on TurboSHAKE128.
pub type TurboShake128FlightDeck = FlightDeck<TurboShake128>;
/// Deck cipher based on TurboSHAKE256.
pub type TurboShake256FlightDeck = FlightDeck<TurboShake256>;
/// Deck cipher based on SHAKE128.
pub type Shake128FlightDeck = FlightDeck<Shake128>;
/// Deck cipher based on SHAKE256.
pub type Shake256FlightDeck = FlightDeck<Shake256>;

/// TurboSHAKE128-BO: authenticated encryption for a session, with tags of `TAG_LEN` bytes.
pub type TurboShake128Bo<const TAG_LEN: usize> = DeckBo<TurboShake128, TAG_LEN>;
/// TurboSHAKE256-BO: authenticated encryption for a session, with tags of `TAG_LEN` bytes.
pub type TurboShake256Bo<const TAG_LEN: usize> = DeckBo<TurboShake256, TAG_LEN>;
/// SHAKE128-BO: authenticated encryption for a session, with tags of `TAG_LEN` bytes.
pub type Shake128Bo<const TAG_LEN: usize> = DeckBo<Shake128, TAG_LEN>;
/// SHAKE256-BO: authenticated encryption for a session, with tags of `TAG_LEN` bytes.
pub type Shake256Bo<const TAG_LEN: usize> = DeckBo<Shake256, TAG_LEN>;

/// The key is too long.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvalidKeyLength;

impl fmt::Display for InvalidKeyLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the key is too long")
    }
}

impl core::error::Error for InvalidKeyLength {}

/// The message, its associated data or its tag was modified, or messages were not decrypted in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AuthenticationError;

impl fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("authentication failed")
    }
}

impl core::error::Error for AuthenticationError {}
