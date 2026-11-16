//! FlightDeck: a deck cipher made of duplex ciphers that run side by side.

use core::fmt;

use crate::InvalidKeyLength;
use crate::duplex::OverwriteDuplex;
use crate::trailer::{DuplexTrailer, Trailer};
use crate::variant::{MAX_BLOCK_LEN, Variant};

const COUNTER_TRAILER: DuplexTrailer = DuplexTrailer(0b10);
const CHAINING_VALUE_TRAILER: DuplexTrailer = DuplexTrailer(0b100);

/// A deck cipher: like a duplex cipher, but inputs and outputs can have any length.
///
/// Each call to [`duplex()`](Self::duplex) absorbs an input, and returns bytes that depend on the key and on every input so far.
/// [`squeeze()`](Self::squeeze) and [`xor()`](Self::xor) give more of them.
///
/// ```
/// use flightdeck::{Trailer, TurboShake128FlightDeck};
///
/// let mut deck = TurboShake128FlightDeck::new(b"sixteen byte key")?;
///
/// let mut tag = [0; 32];
/// deck.duplex(b"a message of any length", Trailer::EMPTY, &mut tag);
///
/// let mut keystream = [0; 1000];
/// deck.squeeze(&mut keystream);
/// # Ok::<(), flightdeck::InvalidKeyLength>(())
/// ```
#[derive(Clone)]
pub struct FlightDeck<V: Variant> {
    duplex: OverwriteDuplex<V>,
    /// A clone of `duplex` that gives the current output block, after the first one.
    squeezer: Option<OverwriteDuplex<V>>,
    /// How many bytes of output were squeezed, or `None` before the first call to `duplex()`.
    offset: Option<u64>,
}

impl<V: Variant> FlightDeck<V> {
    /// Recommended key length, in bytes.
    pub const KEY_LEN: usize = V::KEY_LEN;
    /// Maximum key length, in bytes.
    pub const KEY_LEN_MAX: usize = V::KEY_LEN_MAX;

    /// Set the key, of up to [`KEY_LEN_MAX`](Self::KEY_LEN_MAX) bytes.
    ///
    /// Nothing can be squeezed before the first call to [`duplex()`](Self::duplex).
    pub fn new(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        Ok(Self::from_duplex(OverwriteDuplex::new(key)?))
    }

    /// A clone that can only call [`duplex()`](Self::duplex): it can't squeeze what's left of the current output.
    #[must_use]
    pub fn clone_compact(&self) -> Self {
        Self::from_duplex(self.duplex.clone_compact())
    }

    fn from_duplex(duplex: OverwriteDuplex<V>) -> Self {
        Self {
            duplex,
            squeezer: None,
            offset: None,
        }
    }

    /// Absorb an input of any length and its trailer, then squeeze `output`.
    pub fn duplex(&mut self, input: &[u8], trailer: Trailer, output: &mut [u8]) {
        let last_trailer = trailer.with_bit(true);
        if input.len() <= V::CHUNK_LEN {
            absorb(&mut self.duplex, input, last_trailer);
        } else {
            self.absorb_chunks(input, last_trailer);
        }
        self.offset = Some(0);
        self.squeeze(output);
    }

    /// Squeeze more bytes after a call to [`duplex()`](Self::duplex).
    ///
    /// Squeezing in several calls gives the same bytes as squeezing in one call.
    ///
    /// # Panics
    ///
    /// If [`duplex()`](Self::duplex) was never called.
    pub fn squeeze(&mut self, output: &mut [u8]) {
        // Short outputs are the common case, so what's left of the first block is written directly.
        // The rest is zeroed and goes through `xor()`.
        let offset = self.offset.expect(NO_OUTPUT);
        let left = (V::BLOCK_LEN as u64).saturating_sub(offset) as usize;
        let (head, rest) = output.split_at_mut(output.len().min(left));
        self.duplex.squeeze(head);
        self.offset = Some(offset + head.len() as u64);
        if !rest.is_empty() {
            rest.fill(0);
            self.xor(rest);
        }
    }

    /// Like [`squeeze()`](Self::squeeze), but XOR the bytes into `data` instead of writing them there.
    ///
    /// That's how a deck cipher encrypts and decrypts.
    ///
    /// # Panics
    ///
    /// If [`duplex()`](Self::duplex) was never called.
    pub fn xor(&mut self, mut data: &mut [u8]) {
        // The first block comes from the main duplex.
        // Block `i` comes from a clone of it that absorbs the number `i`.
        let mut offset = self.offset.expect(NO_OUTPUT);

        if offset < V::BLOCK_LEN as u64 {
            let (head, rest) = data.split_at_mut(data.len().min(V::BLOCK_LEN - offset as usize));
            self.duplex.xor(head);
            offset += head.len() as u64;
            data = rest;
        }
        let used = (offset % V::BLOCK_LEN as u64) as usize;
        if used != 0 && !data.is_empty() {
            let squeezer = self.squeezer.as_mut().expect("an output block was started");
            let (head, rest) = data.split_at_mut(data.len().min(V::BLOCK_LEN - used));
            squeezer.xor(head);
            offset += head.len() as u64;
            data = rest;
        }

        while !data.is_empty() {
            let index = offset / V::BLOCK_LEN as u64;
            let squeezer = self.squeezer.get_or_insert_with(OverwriteDuplex::blank);
            squeezer.clone_with_counter_from(&self.duplex, index, COUNTER_TRAILER);
            let (head, rest) = data.split_at_mut(data.len().min(V::BLOCK_LEN));
            squeezer.xor(head);
            offset += head.len() as u64;
            data = rest;
        }
        self.offset = Some(offset);
    }

    /// Absorb an input made of several chunks.
    ///
    /// The main duplex absorbs the first chunk, then a chaining value for each of the other chunks.
    /// Each chaining value comes from a clone of the main duplex that absorbs one chunk.
    fn absorb_chunks(&mut self, input: &[u8], last_trailer: DuplexTrailer) {
        let start = self.duplex.clone_compact();
        let mut root = Root::new();
        let (first, chunks) = input.split_at(V::CHUNK_LEN);
        root.update(&mut self.duplex, first);
        for chunk in chunks.chunks(V::CHUNK_LEN) {
            let mut clone = start.clone();
            let mut cv = [0; MAX_BLOCK_LEN];
            absorb(&mut clone, chunk, CHAINING_VALUE_TRAILER);
            clone.squeeze(&mut cv[..V::CV_LEN]);
            root.update(&mut self.duplex, &cv[..V::CV_LEN]);
        }
        root.finish(&mut self.duplex, last_trailer);
    }
}

impl<V: Variant> fmt::Debug for FlightDeck<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlightDeck").finish_non_exhaustive()
    }
}

const NO_OUTPUT: &str = "duplex() must be called before squeezing";

/// Absorb the blocks of a string, except the last one.
/// Returns what's left: at most `BLOCK_LEN` bytes.
fn absorb_blocks<'a, V: Variant>(duplex: &mut OverwriteDuplex<V>, mut input: &'a [u8]) -> &'a [u8] {
    while input.len() > V::BLOCK_LEN {
        let (block, rest) = input.split_at(V::BLOCK_LEN);
        duplex.absorb(block, DuplexTrailer::EMPTY);
        input = rest;
    }
    input
}

/// Absorb a string of any length, block by block.
/// Only the last block gets the trailer.
fn absorb<V: Variant>(duplex: &mut OverwriteDuplex<V>, input: &[u8], last_trailer: DuplexTrailer) {
    let last = absorb_blocks(duplex, input);
    duplex.absorb(last, last_trailer);
}

/// What the main duplex absorbs when there are several chunks.
/// It comes in pieces, and the last block has to wait for its trailer.
struct Root {
    buf: [u8; MAX_BLOCK_LEN],
    len: usize,
}

impl Root {
    fn new() -> Self {
        Self {
            buf: [0; MAX_BLOCK_LEN],
            len: 0,
        }
    }

    fn update<V: Variant>(&mut self, duplex: &mut OverwriteDuplex<V>, mut bytes: &[u8]) {
        if self.len > 0 {
            let (head, rest) = bytes.split_at(bytes.len().min(V::BLOCK_LEN - self.len));
            self.buf[self.len..][..head.len()].copy_from_slice(head);
            self.len += head.len();
            if rest.is_empty() {
                return;
            }
            duplex.absorb(&self.buf[..V::BLOCK_LEN], DuplexTrailer::EMPTY);
            bytes = rest;
        }
        let last = absorb_blocks(duplex, bytes);
        self.buf[..last.len()].copy_from_slice(last);
        self.len = last.len();
    }

    fn finish<V: Variant>(self, duplex: &mut OverwriteDuplex<V>, last_trailer: DuplexTrailer) {
        duplex.absorb(&self.buf[..self.len], last_trailer);
    }
}
