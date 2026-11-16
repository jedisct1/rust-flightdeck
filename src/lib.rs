//! FlightDeck, a fast keyed cipher built on Keccak.
//!
//! There are two layers:
//!
//! - [`OverwriteDuplex`] is a duplex cipher.
//!   It absorbs a block, and gives back up to a block of output.
//! - [`FlightDeck`] is a deck cipher, built on the duplex cipher.
//!   Same thing, with inputs and outputs of any length.
//!
//! Each layer comes in four instances.
//! [`TurboShake128`] and [`TurboShake256`] are the fast ones.
//! [`Shake128`] and [`Shake256`] use twice as many rounds.

#![no_std]
#![warn(missing_docs)]

#[cfg(test)]
extern crate std;

mod deck;
mod duplex;
mod keccak;
#[cfg(test)]
mod tests;
mod trailer;
mod variant;

use core::fmt;

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

/// The key is too long.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvalidKeyLength;

impl fmt::Display for InvalidKeyLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the key is too long")
    }
}

impl core::error::Error for InvalidKeyLength {}
