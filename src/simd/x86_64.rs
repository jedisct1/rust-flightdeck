//! x86-64: two states at once with SSE2.
//!
//! This file is only built for targets with SSE2.

use core::arch::x86_64::{
    __m128i, _mm_andnot_si128, _mm_loadu_si128, _mm_or_si128, _mm_slli_epi64, _mm_srli_epi64,
    _mm_storeu_si128, _mm_unpackhi_epi64, _mm_unpacklo_epi64, _mm_xor_si128,
};

use crate::batch::Job;
use crate::keccak::Lanes;

#[derive(Clone, Copy)]
struct Sse2(__m128i);

// SAFETY, for every `unsafe` block below: this file is only built for targets with SSE2.
// Loads and stores go through references to arrays of the right size, and don't need them aligned.
impl Lanes<2> for Sse2 {
    const UNROLL: bool = true;

    #[inline(always)]
    fn splat(lane: u64) -> Self {
        Self::from_array([lane; 2])
    }

    #[inline(always)]
    fn from_array(lanes: [u64; 2]) -> Self {
        let mut bytes = [0; 16];
        for (bytes, lane) in bytes.as_chunks_mut().0.iter_mut().zip(lanes) {
            *bytes = lane.to_le_bytes();
        }
        Self::load(&bytes)
    }

    #[inline(always)]
    fn to_array(self) -> [u64; 2] {
        let mut bytes = [0; 16];
        self.store(&mut bytes);
        let mut lanes = [0; 2];
        for (lane, bytes) in lanes.iter_mut().zip(bytes.as_chunks().0) {
            *lane = u64::from_le_bytes(*bytes);
        }
        lanes
    }

    #[inline(always)]
    fn load(bytes: &[u8]) -> Self {
        let bytes: &[u8; 16] = bytes.first_chunk().unwrap();
        Self(unsafe { _mm_loadu_si128(bytes.as_ptr().cast()) })
    }

    #[inline(always)]
    fn store(self, out: &mut [u8]) {
        let out: &mut [u8; 16] = out.first_chunk_mut().unwrap();
        unsafe { _mm_storeu_si128(out.as_mut_ptr().cast(), self.0) };
    }

    #[inline(always)]
    fn transpose([a, b]: [Self; 2]) -> [Self; 2] {
        unsafe {
            [
                Self(_mm_unpacklo_epi64(a.0, b.0)),
                Self(_mm_unpackhi_epi64(a.0, b.0)),
            ]
        }
    }

    #[inline(always)]
    fn xor(self, other: Self) -> Self {
        Self(unsafe { _mm_xor_si128(self.0, other.0) })
    }

    #[inline(always)]
    fn and_not(self, other: Self) -> Self {
        Self(unsafe { _mm_andnot_si128(self.0, other.0) })
    }

    #[inline(always)]
    fn rotl<const L: i32, const R: i32>(self) -> Self {
        Self(unsafe { _mm_or_si128(_mm_slli_epi64::<L>(self.0), _mm_srli_epi64::<R>(self.0)) })
    }
}

pub(crate) fn parallelism() -> usize {
    2
}

pub(crate) fn run<J: Job>(_n: usize, job: J) -> J::Out {
    job.run::<Sse2, 2>()
}
