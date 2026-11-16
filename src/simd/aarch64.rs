//! AArch64 with NEON: two states at once.

use core::arch::aarch64::{
    uint64x2_t, vbicq_u64, vdupq_n_u64, veorq_u64, vld1q_u8, vld1q_u64, vorrq_u64,
    vreinterpretq_u8_u64, vreinterpretq_u64_u8, vshlq_n_u64, vshrq_n_u64, vst1q_u8, vst1q_u64,
    vtrn1q_u64, vtrn2q_u64,
};

use crate::batch::Job;
use crate::keccak::Lanes;

#[derive(Clone, Copy)]
struct Neon(uint64x2_t);

// SAFETY, for every `unsafe` block below: this file is only built for targets with NEON.
// Loads and stores go through references to arrays of the right size.
impl Lanes<2> for Neon {
    const UNROLL: bool = true;

    #[inline(always)]
    fn splat(lane: u64) -> Self {
        Self(unsafe { vdupq_n_u64(lane) })
    }

    #[inline(always)]
    fn from_array(lanes: [u64; 2]) -> Self {
        Self(unsafe { vld1q_u64(lanes.as_ptr()) })
    }

    #[inline(always)]
    fn to_array(self) -> [u64; 2] {
        let mut lanes = [0; 2];
        unsafe { vst1q_u64(lanes.as_mut_ptr(), self.0) };
        lanes
    }

    #[inline(always)]
    fn load(bytes: &[u8]) -> Self {
        let bytes: &[u8; 16] = bytes.first_chunk().unwrap();
        Self(unsafe { vreinterpretq_u64_u8(vld1q_u8(bytes.as_ptr())) })
    }

    #[inline(always)]
    fn store(self, out: &mut [u8]) {
        let out: &mut [u8; 16] = out.first_chunk_mut().unwrap();
        unsafe { vst1q_u8(out.as_mut_ptr(), vreinterpretq_u8_u64(self.0)) };
    }

    #[inline(always)]
    fn transpose([a, b]: [Self; 2]) -> [Self; 2] {
        unsafe { [Self(vtrn1q_u64(a.0, b.0)), Self(vtrn2q_u64(a.0, b.0))] }
    }

    #[inline(always)]
    fn xor(self, other: Self) -> Self {
        Self(unsafe { veorq_u64(self.0, other.0) })
    }

    #[inline(always)]
    fn and_not(self, other: Self) -> Self {
        Self(unsafe { vbicq_u64(other.0, self.0) })
    }

    #[inline(always)]
    fn rotl<const L: i32, const R: i32>(self) -> Self {
        Self(unsafe { vorrq_u64(vshlq_n_u64::<L>(self.0), vshrq_n_u64::<R>(self.0)) })
    }
}

pub(crate) fn parallelism() -> usize {
    2
}

pub(crate) fn run<J: Job>(_n: usize, job: J) -> J::Out {
    job.run::<Neon, 2>()
}
