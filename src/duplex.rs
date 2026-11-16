//! The overwrite duplex construction, on top of Keccak-p[1600].

use core::fmt;
use core::marker::PhantomData;

use crate::InvalidKeyLength;
use crate::batch::MAX_PARALLELISM;
use crate::keccak::{self, Lanes};
use crate::trailer::{DuplexTrailer, append_bit};
use crate::variant::{MAX_BLOCK_LEN, Variant};

/// A duplex cipher: the lowest layer, which works one block at a time.
///
/// It takes a block of up to [`BLOCK_LEN`](Self::BLOCK_LEN) bytes, and gives back up to `BLOCK_LEN` bytes.
/// These bytes depend on the key and on every block so far.
///
/// You most likely want [`FlightDeck`](crate::FlightDeck) instead:
/// it takes inputs and gives outputs of any length, and it's faster on long ones.
///
/// ```
/// use flightdeck::{DuplexTrailer, TurboShake128Duplex};
///
/// let mut duplex = TurboShake128Duplex::new(b"sixteen byte key")?;
/// let mut out = [0; 32];
/// duplex.duplex(b"a block", DuplexTrailer::EMPTY, &mut out);
/// # Ok::<(), flightdeck::InvalidKeyLength>(())
/// ```
#[derive(Clone)]
pub struct OverwriteDuplex<V: Variant> {
    st: [u64; 25],
    /// How many bytes of the current output were squeezed.
    offset: usize,
    variant: PhantomData<V>,
}

impl<V: Variant> OverwriteDuplex<V> {
    /// How many bytes [`duplex()`](Self::duplex) can absorb, and how many can be squeezed after it.
    pub const BLOCK_LEN: usize = V::BLOCK_LEN;
    /// Recommended key length, in bytes.
    pub const KEY_LEN: usize = V::KEY_LEN;
    /// Maximum key length, in bytes.
    pub const KEY_LEN_MAX: usize = V::KEY_LEN_MAX;

    /// Set the key, of up to [`KEY_LEN_MAX`](Self::KEY_LEN_MAX) bytes.
    ///
    /// Nothing can be squeezed before the first call to [`duplex()`](Self::duplex).
    pub fn new(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        if key.len() > V::KEY_LEN_MAX {
            return Err(InvalidKeyLength);
        }
        let mut duplex = Self::blank();
        duplex.absorb(key, DuplexTrailer::EMPTY);
        duplex.offset = V::BLOCK_LEN;
        Ok(duplex)
    }

    /// A clone that can only call [`duplex()`](Self::duplex): it can't squeeze what's left of the current output.
    #[must_use]
    pub fn clone_compact(&self) -> Self {
        let mut clone = Self::blank();
        clone.st[V::BLOCK_LANES..].copy_from_slice(&self.st[V::BLOCK_LANES..]);
        clone
    }

    /// Absorb a block and its trailer, then squeeze `output`.
    ///
    /// # Panics
    ///
    /// If `block` or `output` is longer than [`BLOCK_LEN`](Self::BLOCK_LEN).
    pub fn duplex(&mut self, block: &[u8], trailer: DuplexTrailer, output: &mut [u8]) {
        assert!(
            block.len() <= V::BLOCK_LEN && output.len() <= V::BLOCK_LEN,
            "a block and what comes out after it are at most {} bytes long",
            V::BLOCK_LEN
        );

        self.absorb(block, trailer);
        self.squeeze(output);
    }

    /// Like [`duplex()`](Self::duplex), with nothing squeezed.
    #[inline]
    pub(crate) fn absorb(&mut self, block: &[u8], trailer: DuplexTrailer) {
        debug_assert!(block.len() <= V::BLOCK_LEN);

        let full = block.len() == V::BLOCK_LEN;
        let (lanes, rest) = block.as_chunks();
        for (lane, bytes) in self.st.iter_mut().zip(lanes) {
            *lane = u64::from_le_bytes(*bytes);
        }
        if !full {
            // A short block is followed by a 1 bit, then by zeros.
            let mut last = [0; 8];
            last[..rest.len()].copy_from_slice(rest);
            last[rest.len()] = 0x01;
            self.st[lanes.len()] = u64::from_le_bytes(last);
            self.st[lanes.len() + 1..V::BLOCK_LANES].fill(0);
        }
        self.st[V::BLOCK_LANES] ^= trailer_lane::<V>(trailer, full);
        keccak::permute(&mut self.st, V::ROUNDS);
        self.offset = 0;
    }

    /// Squeeze more bytes after a call to [`duplex()`](Self::duplex).
    ///
    /// # Panics
    ///
    /// If that makes more than [`BLOCK_LEN`](Self::BLOCK_LEN) bytes since the last call to `duplex()`.
    pub fn squeeze(&mut self, output: &mut [u8]) {
        self.output::<false>(output);
    }

    /// Like [`squeeze()`](Self::squeeze), but XOR the bytes into `data`.
    ///
    /// # Panics
    ///
    /// When [`squeeze()`](Self::squeeze) does.
    pub fn xor(&mut self, data: &mut [u8]) {
        self.output::<true>(data);
    }

    /// A placeholder, to be overwritten.
    pub(crate) fn blank() -> Self {
        Self {
            st: [0; 25],
            offset: V::BLOCK_LEN,
            variant: PhantomData,
        }
    }

    /// Become a compact clone of `other` that has absorbed `counter` as a block.
    ///
    /// Same as `clone_compact()` then `duplex()`, without copying the state around.
    pub(crate) fn clone_with_counter_from(
        &mut self,
        other: &Self,
        counter: u64,
        trailer: DuplexTrailer,
    ) {
        self.st[0] = counter;
        self.st[1..V::BLOCK_LANES].fill(0);
        self.st[V::BLOCK_LANES..].copy_from_slice(&other.st[V::BLOCK_LANES..]);
        self.st[V::BLOCK_LANES] ^= trailer_lane::<V>(trailer, true);
        keccak::permute(&mut self.st, V::ROUNDS);
        self.offset = 0;
    }

    fn output<const XOR: bool>(&mut self, data: &mut [u8]) {
        assert!(
            data.len() <= V::BLOCK_LEN - self.offset,
            "a duplex cipher gives at most {} bytes per call to duplex()",
            V::BLOCK_LEN
        );

        // The end of a lane, whole lanes, then the start of a lane.
        let head_len = (self.offset.next_multiple_of(8) - self.offset).min(data.len());
        let (head, rest) = data.split_at_mut(head_len);
        let (whole_lanes, tail) = rest.as_chunks_mut();
        let mut next = self.offset / 8;
        if !head.is_empty() {
            let bytes = self.st[next].to_le_bytes();
            store::<XOR>(head, &bytes[self.offset % 8..]);
            next += 1;
        }
        for (out, lane) in whole_lanes.iter_mut().zip(&self.st[next..]) {
            store_lane::<XOR>(out, *lane);
        }
        if !tail.is_empty() {
            let bytes = self.st[next + whole_lanes.len()].to_le_bytes();
            store::<XOR>(tail, &bytes);
        }
        self.offset += data.len();
    }
}

impl<V: Variant> fmt::Debug for OverwriteDuplex<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OverwriteDuplex").finish_non_exhaustive()
    }
}

/// The lane right after a block: its trailer, and the padding of the sponge function.
#[inline(always)]
fn trailer_lane<V: Variant>(trailer: DuplexTrailer, full: bool) -> u64 {
    append_bit(trailer.0, full) as u64 | (V::PADDING as u64) << 56
}

/// Write a lane to `out`, or XOR it into it.
#[inline(always)]
fn store_lane<const XOR: bool>(out: &mut [u8; 8], lane: u64) {
    let lane = if XOR {
        lane ^ u64::from_le_bytes(*out)
    } else {
        lane
    };
    *out = lane.to_le_bytes();
}

/// Write the first bytes of `bytes` to `out`, or XOR them into it.
#[inline(always)]
pub(crate) fn store<const XOR: bool>(out: &mut [u8], bytes: &[u8]) {
    let bytes = &bytes[..out.len()];
    let (lanes, rest) = out.as_chunks_mut();
    let (lanes_in, rest_in) = bytes.as_chunks();
    for (out, lane) in lanes.iter_mut().zip(lanes_in) {
        store_lane::<XOR>(out, u64::from_le_bytes(*lane));
    }
    for (o, b) in rest.iter_mut().zip(rest_in) {
        *o = if XOR { *o ^ b } else { *b };
    }
}

/// `N` compact clones of a duplex cipher, in vectors.
///
/// Like `Lanes`, this has to be inlined into the function built for these vectors, so no closures here either.
pub(crate) struct Clones<V: Variant, L: Lanes<N>, const N: usize> {
    /// `st[i]` is the lane `i` of every clone.
    st: [L; 25],
    variant: PhantomData<V>,
}

impl<V: Variant, L: Lanes<N>, const N: usize> Clones<V, L, N> {
    #[inline(always)]
    pub(crate) fn new(duplex: &OverwriteDuplex<V>) -> Self {
        let mut st = [L::splat(0); 25];
        for i in V::BLOCK_LANES..25 {
            st[i] = L::splat(duplex.st[i]);
        }
        Self {
            st,
            variant: PhantomData,
        }
    }

    /// Clone `i`, as a duplex cipher of its own.
    #[inline(always)]
    pub(crate) fn get(&self, i: usize) -> OverwriteDuplex<V> {
        let mut st = [0; 25];
        for (lane, lanes) in st.iter_mut().zip(&self.st) {
            *lane = lanes.to_array()[i];
        }
        OverwriteDuplex {
            st,
            offset: 0,
            variant: PhantomData,
        }
    }

    /// Make each clone absorb its own block.
    /// All the blocks have the same length.
    #[inline(always)]
    pub(crate) fn duplex(&mut self, blocks: [&[u8]; N], trailer: DuplexTrailer) {
        let len = blocks[0].len();
        debug_assert!(len <= V::BLOCK_LEN);

        let full = len == V::BLOCK_LEN;
        if full {
            self.overwrite(blocks);
        } else {
            let mut padded = [[0; MAX_BLOCK_LEN]; N];
            for (buf, block) in padded.iter_mut().zip(&blocks) {
                buf[..len].copy_from_slice(block);
                buf[len] = 0x01;
            }
            let mut blocks = blocks;
            for (block, buf) in blocks.iter_mut().zip(&padded) {
                *block = buf;
            }
            self.overwrite(blocks);
        }
        self.permute(trailer, full);
    }

    /// Make clone `i` absorb the number `first + i` as a block.
    #[inline(always)]
    pub(crate) fn duplex_counters(&mut self, first: u64, trailer: DuplexTrailer) {
        let mut counters = [first; N];
        for (i, counter) in counters.iter_mut().enumerate() {
            *counter += i as u64;
        }
        self.st[0] = L::from_array(counters);
        self.st[1..V::BLOCK_LANES].fill(L::splat(0));
        self.permute(trailer, true);
    }

    /// XOR `len` bytes squeezed from each clone into `data`, one clone after the other.
    #[inline(always)]
    pub(crate) fn xor(&self, len: usize, data: &mut [u8]) {
        debug_assert!(len <= V::BLOCK_LEN);

        // Looks redundant, but WebAssembly is 9% slower without it.
        let data = &mut data[..N * len];
        for from in (0..len.div_ceil(8)).step_by(N) {
            let mut columns = [L::splat(0); N];
            columns.copy_from_slice(&self.st[from..from + N]);
            let rows = L::transpose(columns);
            let size = (len - 8 * from).min(8 * N);
            for (row, out) in rows.iter().zip(data.chunks_exact_mut(len)) {
                let out = &mut out[8 * from..][..size];
                if size < 8 * N {
                    let mut bytes = [0; 8 * MAX_PARALLELISM];
                    row.store(&mut bytes);
                    store::<true>(out, &bytes);
                } else {
                    row.xor(L::load(out)).store(out);
                }
            }
        }
    }

    /// Overwrite the start of each state with a block.
    /// Only the first `BLOCK_LEN` bytes of a block are read.
    #[inline(always)]
    fn overwrite(&mut self, blocks: [&[u8]; N]) {
        for group in 0..V::BLOCK_LANES.div_ceil(N) {
            // When fewer than `N` lanes are left, step back and load a few of them again.
            let from = (group * N).min(V::BLOCK_LANES - N);
            let mut rows = [L::splat(0); N];
            for (row, block) in rows.iter_mut().zip(&blocks) {
                *row = L::load(&block[8 * from..]);
            }
            self.st[from..from + N].copy_from_slice(&L::transpose(rows));
        }
    }

    #[inline(always)]
    fn permute(&mut self, trailer: DuplexTrailer, full: bool) {
        let after_block = &mut self.st[V::BLOCK_LANES];
        *after_block = after_block.xor(L::splat(trailer_lane::<V>(trailer, full)));
        keccak::permute_lanes(&mut self.st, V::ROUNDS);
    }
}
