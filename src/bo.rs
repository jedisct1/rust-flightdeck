//! Deck-BO: authenticated encryption for a session of messages.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt;
use core::hint::black_box;

use crate::deck::FlightDeck;
use crate::trailer::Trailer;
use crate::variant::Variant;
use crate::{AuthenticationError, InvalidKeyLength};

const AD_ONLY_TRAILER: Trailer = Trailer(0b100);
const AD_TRAILER: Trailer = Trailer(0b101);
const TAG_TRAILER: Trailer = Trailer(0b1101);
const MESSAGE_TRAILER: Trailer = Trailer(0b1110);

/// Authenticated encryption for a session: a sequence of messages between two parties that share a key.
///
/// Each message can come with associated data, which is authenticated but not encrypted.
/// It gets a tag of `TAG_LEN` bytes, that covers the whole session up to that message.
/// So messages have to be decrypted in the order they were encrypted.
///
/// There's no nonce.
/// Encrypt the same message at the same point of two sessions with the same key, and you get the same ciphertext.
/// Besides the length of the message, that's all a ciphertext gives away.
/// If that matters to you, put a nonce or a counter in the associated data.
///
/// `TAG_LEN` can't be 0: that's an error when the program is built.
/// With twice the security level, so 32 bytes for the 128-bit instances,
/// a tag also commits to the key, the associated data and the message.
///
/// ```
/// use flightdeck::TurboShake128Bo;
///
/// let key = [0x42; 16];
/// let mut sender = TurboShake128Bo::<16>::new(&key)?;
/// let mut receiver = TurboShake128Bo::<16>::new(&key)?;
///
/// let mut buffer = *b"hello";
/// let tag = sender.encrypt_in_place(b"associated data", &mut buffer);
/// receiver.decrypt_in_place(b"associated data", &mut buffer, &tag)?;
/// assert_eq!(&buffer, b"hello");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct DeckBo<V: Variant, const TAG_LEN: usize> {
    deck: FlightDeck<V>,
}

impl<V: Variant, const TAG_LEN: usize> DeckBo<V, TAG_LEN> {
    /// Length of the authentication tag, in bytes.
    pub const TAG_LEN: usize = TAG_LEN;
    /// Recommended key length, in bytes.
    pub const KEY_LEN: usize = V::KEY_LEN;
    /// Maximum key length, in bytes.
    pub const KEY_LEN_MAX: usize = V::KEY_LEN_MAX;

    /// Start a session, with a key of up to [`KEY_LEN_MAX`](Self::KEY_LEN_MAX) bytes.
    pub fn new(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        const { assert!(TAG_LEN > 0, "TAG_LEN can't be 0") };
        Ok(Self {
            deck: FlightDeck::new(key)?,
        })
    }

    /// Encrypt the next message of the session in place, and return its tag.
    #[must_use = "the message can't be decrypted without its tag"]
    pub fn encrypt_in_place(&mut self, associated_data: &[u8], buffer: &mut [u8]) -> [u8; TAG_LEN] {
        let mut tag = [0; TAG_LEN];
        if buffer.is_empty() {
            self.deck.duplex(associated_data, AD_ONLY_TRAILER, &mut tag);
            return tag;
        }
        if !associated_data.is_empty() {
            self.deck.duplex(associated_data, AD_TRAILER, &mut []);
        }
        let mut keystream = self.deck.clone_compact();
        self.deck.duplex(buffer, MESSAGE_TRAILER, &mut tag);
        keystream.duplex(&tag, TAG_TRAILER, &mut []);
        keystream.xor(buffer);
        tag
    }

    /// Decrypt the next message of the session in place.
    ///
    /// If the tag doesn't match, the buffer is zeroed and the session stays as it was.
    pub fn decrypt_in_place(
        &mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), AuthenticationError> {
        let saved = self.deck.clone_compact();
        let deck = &mut self.deck;
        let mut computed_tag = [0; TAG_LEN];
        if buffer.is_empty() {
            deck.duplex(associated_data, AD_ONLY_TRAILER, &mut computed_tag);
        } else {
            if !associated_data.is_empty() {
                deck.duplex(associated_data, AD_TRAILER, &mut []);
            }
            let mut keystream = deck.clone_compact();
            keystream.duplex(tag, TAG_TRAILER, &mut []);
            keystream.xor(buffer);
            deck.duplex(buffer, MESSAGE_TRAILER, &mut computed_tag);
        }
        if !constant_time_eq(&computed_tag, tag) {
            buffer.fill(0);
            self.deck = saved;
            return Err(AuthenticationError);
        }
        Ok(())
    }

    /// Encrypt the next message of the session, and return the ciphertext followed by the tag.
    #[cfg(feature = "alloc")]
    #[must_use = "the session moved on: the ciphertext can't be made again"]
    pub fn encrypt(&mut self, associated_data: &[u8], message: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(message.len() + TAG_LEN);
        out.extend_from_slice(message);
        let tag = self.encrypt_in_place(associated_data, &mut out);
        out.extend_from_slice(&tag);
        out
    }

    /// Decrypt the next message of the session, from what [`encrypt()`](Self::encrypt) returned.
    ///
    /// If it doesn't authenticate, the session stays as it was.
    #[cfg(feature = "alloc")]
    pub fn decrypt(
        &mut self,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AuthenticationError> {
        let (ciphertext, tag) = ciphertext.split_last_chunk().ok_or(AuthenticationError)?;
        let mut message = ciphertext.to_vec();
        self.decrypt_in_place(associated_data, &mut message, tag)?;
        Ok(message)
    }
}

impl<V: Variant, const TAG_LEN: usize> fmt::Debug for DeckBo<V, TAG_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeckBo").finish_non_exhaustive()
    }
}

/// Compare two tags, in a time that doesn't depend on where they differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let difference = a
        .iter()
        .zip(b)
        .fold(0, |difference, (x, y)| difference | (x ^ y));
    black_box(difference) == 0
}
