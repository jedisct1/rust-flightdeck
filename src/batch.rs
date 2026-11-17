//! The two jobs done on several states at once: absorbing chunks, and making output blocks.

use crate::duplex::{Clones, OverwriteDuplex};
use crate::keccak::Lanes;
use crate::trailer::DuplexTrailer;
use crate::variant::Variant;

pub(crate) const COUNTER_TRAILER: DuplexTrailer = DuplexTrailer(0b10);
pub(crate) const CHAINING_VALUE_TRAILER: DuplexTrailer = DuplexTrailer(0b100);

/// The most clones any backend runs at once in vectors.
pub(crate) const MAX_PARALLELISM: usize = 8;

/// Something to do on `N` states at once.
///
/// Like `Lanes`, `run()` has to be inlined into the function built for the vectors.
pub(crate) trait Job {
    type Out;

    fn run<L: Lanes<N>, const N: usize>(self) -> Self::Out;
}

/// Absorb chunks that all start from the same state, one chunk per clone.
pub(crate) struct Absorb<'a, V: Variant> {
    pub(crate) start: &'a OverwriteDuplex<V>,
    pub(crate) chunks: &'a [u8],
    /// How many whole chunks there are.
    pub(crate) count: usize,
    /// How many bytes of the next chunk, a shorter one, are absorbed too.
    pub(crate) tail_len: usize,
    /// The chaining value of every clone is XORed in here.
    pub(crate) cvs: &'a mut [u8],
    /// Gets the first clone as a compact clone, as it is right before the last block of its chunk.
    pub(crate) first: Option<&'a mut OverwriteDuplex<V>>,
    /// Whether one more chunk is absorbed, by a clone on general registers.
    /// Its chaining value comes after the others.
    /// Only when every clone has a whole chunk.
    pub(crate) one_more: bool,
}

impl<'a, V: Variant> Absorb<'a, V> {
    /// What each clone absorbs, `offset` bytes into its chunk.
    /// A clone with nothing to do absorbs the same block as the first one.
    #[inline(always)]
    fn blocks_at<const N: usize>(&self, offset: usize, len: usize) -> [&'a [u8]; N] {
        let mut blocks = [&self.chunks[offset..][..len]; N];
        for (i, block) in blocks.iter_mut().enumerate().skip(1) {
            if i < self.count || (i == self.count && offset < self.tail_len) {
                *block = &self.chunks[i * V::CHUNK_LEN + offset..][..len];
            }
        }
        blocks
    }
}

impl<V: Variant> Absorb<'_, V> {
    #[inline(always)]
    fn run_with_one_more<L: Lanes<N>, const N: usize>(self) {
        debug_assert!(self.count == N && self.tail_len == 0);

        let mut clones = Clones::<V, L, N>::new(self.start);
        let mut one = self.start.clone_compact();
        let one_chunk = &self.chunks[N * V::CHUNK_LEN..][..V::CHUNK_LEN];
        let mut done = 0;
        while done < V::CHUNK_LEN - V::LAST_BLOCK_LEN {
            clones.absorb_with_one(
                self.blocks_at(done, V::BLOCK_LEN),
                &mut one,
                &one_chunk[done..][..V::BLOCK_LEN],
                DuplexTrailer::EMPTY,
            );
            done += V::BLOCK_LEN;
        }
        let last_blocks = self.blocks_at(done, V::LAST_BLOCK_LEN);
        if let Some(first) = self.first {
            clones.put_compact(0, first);
        }
        clones.absorb_with_one(
            last_blocks,
            &mut one,
            &one_chunk[done..],
            CHAINING_VALUE_TRAILER,
        );
        let (cvs, one_cv) = self.cvs.split_at_mut(N * V::CV_LEN);
        clones.output::<true>(V::CV_LEN, cvs);
        one.xor(&mut one_cv[..V::CV_LEN]);
    }
}

impl<V: Variant> Job for Absorb<'_, V> {
    /// The clone of the shorter chunk, as a compact clone, once it has absorbed `tail_len` bytes.
    type Out = Option<OverwriteDuplex<V>>;

    #[inline(always)]
    fn run<L: Lanes<N>, const N: usize>(self) -> Self::Out {
        if self.one_more {
            self.run_with_one_more::<L, N>();
            return None;
        }

        let mut clones = Clones::<V, L, N>::new(self.start);
        let mut tail = None;
        let mut done = 0;
        loop {
            if self.tail_len != 0 && done == self.tail_len {
                tail = Some(clones.get_compact(self.count));
            }
            if done == V::CHUNK_LEN - V::LAST_BLOCK_LEN {
                break;
            }
            clones.absorb(self.blocks_at(done, V::BLOCK_LEN), DuplexTrailer::EMPTY);
            done += V::BLOCK_LEN;
        }
        let last_blocks = self.blocks_at(done, V::LAST_BLOCK_LEN);
        if let Some(first) = self.first {
            clones.put_compact(0, first);
        }
        clones.duplex(last_blocks, CHAINING_VALUE_TRAILER);
        clones.output::<true>(V::CV_LEN, self.cvs);
        tail
    }
}

/// Absorb the blocks of a string one after the other, on a single state.
///
/// As a job, it's built for the vectors of the CPU and keeps the state in registers between blocks.
pub(crate) struct AbsorbBlocks<'a, V: Variant> {
    /// Comes out as a compact clone.
    pub(crate) duplex: &'a mut OverwriteDuplex<V>,
    /// Full blocks, with more to absorb after the last one.
    pub(crate) blocks: &'a [u8],
}

impl<V: Variant> Job for AbsorbBlocks<'_, V> {
    type Out = ();

    #[inline(always)]
    fn run<L: Lanes<N>, const N: usize>(self) {
        let mut clones = Clones::<V, L, N>::new(self.duplex);
        for block in self.blocks.chunks_exact(V::BLOCK_LEN) {
            clones.absorb([block; N], DuplexTrailer::EMPTY);
        }
        clones.put_compact(0, self.duplex);
    }
}

/// Make consecutive output blocks, one per clone.
pub(crate) struct Output<'a, V: Variant> {
    pub(crate) duplex: &'a OverwriteDuplex<V>,
    /// The index of the first block.
    pub(crate) index: u64,
    /// Where the blocks go.
    pub(crate) data: &'a mut [u8],
    /// Whether the blocks are XORed into `data`, and not written over it.
    pub(crate) xor: bool,
    /// A clone to keep, and where to put it.
    pub(crate) keep: Option<(usize, &'a mut OverwriteDuplex<V>)>,
}

impl<V: Variant> Job for Output<'_, V> {
    type Out = ();

    #[inline(always)]
    fn run<L: Lanes<N>, const N: usize>(self) {
        let mut clones = Clones::<V, L, N>::new(self.duplex);
        clones.duplex_counters(self.index, COUNTER_TRAILER);
        if self.xor {
            clones.output::<true>(V::BLOCK_LEN, self.data);
        } else {
            clones.output::<false>(V::BLOCK_LEN, self.data);
        }
        if let Some((i, kept)) = self.keep {
            *kept = clones.get(i);
        }
    }
}
