//! WebAssembly with the `simd128` feature: two states at once.

use core::arch::wasm32::{
    i64x2_shuffle, u64x2, u64x2_extract_lane, u64x2_shl, u64x2_shr, u64x2_splat, v128, v128_andnot,
    v128_load, v128_or, v128_store, v128_xor,
};

use crate::batch::Job;
use crate::keccak::Lanes;

#[derive(Clone, Copy)]
struct V128(v128);

impl Lanes<2> for V128 {
    const UNROLL: bool = false;

    #[inline(always)]
    fn splat(lane: u64) -> Self {
        Self(u64x2_splat(lane))
    }

    #[inline(always)]
    fn from_array(lanes: [u64; 2]) -> Self {
        Self(u64x2(lanes[0], lanes[1]))
    }

    #[inline(always)]
    fn to_array(self) -> [u64; 2] {
        [
            u64x2_extract_lane::<0>(self.0),
            u64x2_extract_lane::<1>(self.0),
        ]
    }

    #[inline(always)]
    fn load(bytes: &[u8]) -> Self {
        let bytes: &[u8; 16] = bytes.first_chunk().unwrap();
        // SAFETY: the pointer is to 16 bytes, and `v128_load()` doesn't need them aligned.
        Self(unsafe { v128_load(bytes.as_ptr().cast()) })
    }

    #[inline(always)]
    fn store(self, out: &mut [u8]) {
        let out: &mut [u8; 16] = out.first_chunk_mut().unwrap();
        // SAFETY: the pointer is to 16 bytes, and `v128_store()` doesn't need them aligned.
        unsafe { v128_store(out.as_mut_ptr().cast(), self.0) };
    }

    #[inline(always)]
    fn transpose([a, b]: [Self; 2]) -> [Self; 2] {
        [
            Self(i64x2_shuffle::<0, 2>(a.0, b.0)),
            Self(i64x2_shuffle::<1, 3>(a.0, b.0)),
        ]
    }

    #[inline(always)]
    fn xor(self, other: Self) -> Self {
        Self(v128_xor(self.0, other.0))
    }

    #[inline(always)]
    fn and_not(self, other: Self) -> Self {
        Self(v128_andnot(other.0, self.0))
    }

    #[inline(always)]
    fn rotl<const L: i32, const R: i32>(self) -> Self {
        Self(v128_or(
            u64x2_shl(self.0, L as u32),
            u64x2_shr(self.0, R as u32),
        ))
    }
}

pub(crate) fn parallelism() -> usize {
    2
}

pub(crate) fn run<J: Job>(_n: usize, job: J) -> J::Out {
    job.run::<V128, 2>()
}
