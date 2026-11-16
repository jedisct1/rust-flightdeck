//! x86-64: two states at once with SSE2, four with AVX2, eight with AVX-512.
//!
//! This file is only built for targets with SSE2.
//! The rest is looked for when the program runs.
//!
//! AVX2 and AVX-512 are also used on fewer states, where they still beat SSE2.
//! AVX-512 means AVX-512F and AVX-512VL here: a CPU with only the first one gets the AVX2 code.

use core::arch::x86_64::{
    __m128i, __m256i, __m512i, _mm_andnot_si128, _mm_loadu_si128, _mm_or_si128, _mm_slli_epi64,
    _mm_srli_epi64, _mm_storeu_si128, _mm_unpackhi_epi64, _mm_unpacklo_epi64, _mm_xor_si128,
    _mm256_andnot_si256, _mm256_loadu_si256, _mm256_or_si256, _mm256_permute2x128_si256,
    _mm256_rol_epi64, _mm256_slli_epi64, _mm256_srli_epi64, _mm256_storeu_si256,
    _mm256_unpackhi_epi64, _mm256_unpacklo_epi64, _mm256_xor_si256, _mm512_andnot_si512,
    _mm512_loadu_si512, _mm512_rol_epi64, _mm512_shuffle_i64x2, _mm512_storeu_si512,
    _mm512_unpackhi_epi64, _mm512_unpacklo_epi64, _mm512_xor_si512,
};

use crate::batch::Job;
use crate::keccak::{self, Lanes};
use crate::simd::portable;

cpufeatures::new!(avx2, "avx2");
cpufeatures::new!(avx512, "avx512f", "avx512vl");
cpufeatures::new!(bmi2, "bmi1", "bmi2");

/// The best vector instructions the CPU has.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Tier {
    Sse2,
    Avx2,
    Avx512,
}

fn tier() -> Tier {
    let tier = if avx512::get() {
        Tier::Avx512
    } else if avx2::get() {
        Tier::Avx2
    } else {
        Tier::Sse2
    };
    #[cfg(test)]
    let tier = tier.min([Tier::Sse2, Tier::Avx2, Tier::Avx512][crate::tests::max_tier().min(2)]);
    tier
}

/// A type for `$n` lanes in a vector, from the intrinsics to use.
///
/// `unroll` is `Lanes::UNROLL`.
/// The best choice depends on the number of registers: 16 before AVX-512, 32 with it.
macro_rules! lanes {
    (
        $(#[$doc:meta])*
        $name:ident: $n:literal lanes in $vector:ty,
        unroll: $unroll:literal,
        load: $load:ident,
        store: $store:ident,
        xor: $xor:ident,
        and_not: $and_not:ident,
        rotl: |$x:ident| $rotl:expr,
        transpose: $transpose:ident($($row:ident),*),
    ) => {
        $(#[$doc])*
        #[derive(Clone, Copy)]
        struct $name($vector);

        // SAFETY, for every `unsafe` block below:
        // this type is only used by functions built for the instructions it needs.
        // Those are SSE2, which the target has, or were found by `tier()` before the call.
        // Loads and stores go through references to arrays of the right size, and don't need them aligned.
        impl Lanes<$n> for $name {
            const UNROLL: bool = $unroll;

            #[inline(always)]
            fn splat(lane: u64) -> Self {
                Self::from_array([lane; $n])
            }

            #[inline(always)]
            fn from_array(lanes: [u64; $n]) -> Self {
                let mut bytes = [0; 8 * $n];
                for (bytes, lane) in bytes.as_chunks_mut().0.iter_mut().zip(lanes) {
                    *bytes = lane.to_le_bytes();
                }
                Self::load(&bytes)
            }

            #[inline(always)]
            fn to_array(self) -> [u64; $n] {
                let mut bytes = [0; 8 * $n];
                self.store(&mut bytes);
                let mut lanes = [0; $n];
                for (lane, bytes) in lanes.iter_mut().zip(bytes.as_chunks().0) {
                    *lane = u64::from_le_bytes(*bytes);
                }
                lanes
            }

            #[inline(always)]
            fn load(bytes: &[u8]) -> Self {
                let bytes: &[u8; 8 * $n] = bytes.first_chunk().unwrap();
                Self(unsafe { $load(bytes.as_ptr().cast()) })
            }

            #[inline(always)]
            fn store(self, out: &mut [u8]) {
                let out: &mut [u8; 8 * $n] = out.first_chunk_mut().unwrap();
                unsafe { $store(out.as_mut_ptr().cast(), self.0) };
            }

            #[inline(always)]
            fn transpose([$($row),*]: [Self; $n]) -> [Self; $n] {
                let [$($row),*] = unsafe { $transpose([$($row.0),*]) };
                [$(Self($row)),*]
            }

            #[inline(always)]
            fn xor(self, other: Self) -> Self {
                Self(unsafe { $xor(self.0, other.0) })
            }

            #[inline(always)]
            fn and_not(self, other: Self) -> Self {
                Self(unsafe { $and_not(self.0, other.0) })
            }

            #[inline(always)]
            fn rotl<const L: i32, const R: i32>(self) -> Self {
                let $x = self.0;
                Self(unsafe { $rotl })
            }
        }
    };
}

lanes!(
    /// Two states.
    /// The kernels built for AVX2 and AVX-512 use it too, and get better instructions out of the same code.
    Sse2: 2 lanes in __m128i,
    unroll: true,
    load: _mm_loadu_si128,
    store: _mm_storeu_si128,
    xor: _mm_xor_si128,
    and_not: _mm_andnot_si128,
    rotl: |x| _mm_or_si128(_mm_slli_epi64::<L>(x), _mm_srli_epi64::<R>(x)),
    transpose: transpose_128(a, b),
);

lanes!(
    Avx2: 4 lanes in __m256i,
    unroll: false,
    load: _mm256_loadu_si256,
    store: _mm256_storeu_si256,
    xor: _mm256_xor_si256,
    and_not: _mm256_andnot_si256,
    rotl: |x| _mm256_or_si256(_mm256_slli_epi64::<L>(x), _mm256_srli_epi64::<R>(x)),
    transpose: transpose_256(a, b, c, d),
);

lanes!(
    /// Like `Avx2`, but AVX-512 has enough registers for the rounds to be written out.
    Avx512x4: 4 lanes in __m256i,
    unroll: true,
    load: _mm256_loadu_si256,
    store: _mm256_storeu_si256,
    xor: _mm256_xor_si256,
    and_not: _mm256_andnot_si256,
    rotl: |x| _mm256_rol_epi64::<L>(x),
    transpose: transpose_256(a, b, c, d),
);

lanes!(
    Avx512: 8 lanes in __m512i,
    unroll: true,
    load: _mm512_loadu_si512,
    store: _mm512_storeu_si512,
    xor: _mm512_xor_si512,
    and_not: _mm512_andnot_si512,
    rotl: |x| _mm512_rol_epi64::<L>(x),
    transpose: transpose_512(a, b, c, d, e, f, g, h),
);

#[inline(always)]
unsafe fn transpose_128([a, b]: [__m128i; 2]) -> [__m128i; 2] {
    unsafe { [_mm_unpacklo_epi64(a, b), _mm_unpackhi_epi64(a, b)] }
}

#[inline(always)]
unsafe fn transpose_256([a, b, c, d]: [__m256i; 4]) -> [__m256i; 4] {
    unsafe {
        // Lanes 0 and 2 of each pair of rows, then lanes 1 and 3.
        let ab_even = _mm256_unpacklo_epi64(a, b);
        let ab_odd = _mm256_unpackhi_epi64(a, b);
        let cd_even = _mm256_unpacklo_epi64(c, d);
        let cd_odd = _mm256_unpackhi_epi64(c, d);
        [
            _mm256_permute2x128_si256::<0x20>(ab_even, cd_even),
            _mm256_permute2x128_si256::<0x20>(ab_odd, cd_odd),
            _mm256_permute2x128_si256::<0x31>(ab_even, cd_even),
            _mm256_permute2x128_si256::<0x31>(ab_odd, cd_odd),
        ]
    }
}

#[inline(always)]
unsafe fn transpose_512([a, b, c, d, e, f, g, h]: [__m512i; 8]) -> [__m512i; 8] {
    unsafe {
        // The lanes at even positions of each pair of rows, then the ones at odd positions.
        let ab_even = _mm512_unpacklo_epi64(a, b);
        let ab_odd = _mm512_unpackhi_epi64(a, b);
        let cd_even = _mm512_unpacklo_epi64(c, d);
        let cd_odd = _mm512_unpackhi_epi64(c, d);
        let ef_even = _mm512_unpacklo_epi64(e, f);
        let ef_odd = _mm512_unpackhi_epi64(e, f);
        let gh_even = _mm512_unpacklo_epi64(g, h);
        let gh_odd = _mm512_unpackhi_epi64(g, h);

        // Same thing on each half of the rows. The names say which positions are left.
        let abcd_04 = _mm512_shuffle_i64x2::<0x88>(ab_even, cd_even);
        let abcd_15 = _mm512_shuffle_i64x2::<0x88>(ab_odd, cd_odd);
        let abcd_26 = _mm512_shuffle_i64x2::<0xdd>(ab_even, cd_even);
        let abcd_37 = _mm512_shuffle_i64x2::<0xdd>(ab_odd, cd_odd);
        let efgh_04 = _mm512_shuffle_i64x2::<0x88>(ef_even, gh_even);
        let efgh_15 = _mm512_shuffle_i64x2::<0x88>(ef_odd, gh_odd);
        let efgh_26 = _mm512_shuffle_i64x2::<0xdd>(ef_even, gh_even);
        let efgh_37 = _mm512_shuffle_i64x2::<0xdd>(ef_odd, gh_odd);

        [
            _mm512_shuffle_i64x2::<0x88>(abcd_04, efgh_04),
            _mm512_shuffle_i64x2::<0x88>(abcd_15, efgh_15),
            _mm512_shuffle_i64x2::<0x88>(abcd_26, efgh_26),
            _mm512_shuffle_i64x2::<0x88>(abcd_37, efgh_37),
            _mm512_shuffle_i64x2::<0xdd>(abcd_04, efgh_04),
            _mm512_shuffle_i64x2::<0xdd>(abcd_15, efgh_15),
            _mm512_shuffle_i64x2::<0xdd>(abcd_26, efgh_26),
            _mm512_shuffle_i64x2::<0xdd>(abcd_37, efgh_37),
        ]
    }
}

/// Make the calling function align its stack to 64 bytes.
///
/// The compiler keeps some vectors on the stack, but only aligns it if it knows early on that something needs it.
/// This is that something.
/// Without it, these vectors can end up across two cache lines, and reading them back is very slow.
#[inline(always)]
fn align_stack() {
    #[repr(align(64))]
    struct Aligned(u8);

    let mut aligned = Aligned(0);
    // SAFETY: the pointer is to a local variable.
    // A volatile write can't be removed, so the variable has to exist.
    unsafe { (&raw mut aligned.0).write_volatile(0) };
}

#[target_feature(enable = "avx2")]
fn run_avx2<J: Job, L: Lanes<N>, const N: usize>(job: J) -> J::Out {
    align_stack();
    job.run::<L, N>()
}

#[target_feature(enable = "avx512f,avx512vl")]
fn run_avx512<J: Job, L: Lanes<N>, const N: usize>(job: J) -> J::Out {
    align_stack();
    job.run::<L, N>()
}

pub(crate) fn parallelism() -> usize {
    match tier() {
        Tier::Sse2 => 2,
        Tier::Avx2 => 4,
        Tier::Avx512 => 8,
    }
}

pub(crate) fn run<J: Job>(n: usize, job: J) -> J::Out {
    // SAFETY: `tier()` says that the CPU has what the function was built for.
    match (tier(), n) {
        (Tier::Avx512, 8) => unsafe { run_avx512::<J, Avx512, 8>(job) },
        (Tier::Avx512, 4) => unsafe { run_avx512::<J, Avx512x4, 4>(job) },
        (Tier::Avx512, 2) => unsafe { run_avx512::<J, Sse2, 2>(job) },
        (Tier::Avx2, 4) => unsafe { run_avx2::<J, Avx2, 4>(job) },
        (Tier::Avx2, 2) => unsafe { run_avx2::<J, Sse2, 2>(job) },
        (Tier::Sse2, 2) => job.run::<Sse2, 2>(),
        _ => unreachable!("{n} states at once, on a CPU that can't do it"),
    }
}

/// The permutation of one state, with BMI.
/// It has instructions for what Keccak does all the time: AND NOT, and rotate into another register.
#[target_feature(enable = "bmi1,bmi2")]
fn permute_bmi2(st: &mut [u64; 25], rounds: usize) {
    keccak::permute(st, rounds);
}

pub(crate) fn permute(st: &mut [u64; 25], rounds: usize) {
    let bmi2 = bmi2::get();
    #[cfg(test)]
    let bmi2 = bmi2 && crate::tests::max_tier() > 0;
    if bmi2 {
        // SAFETY: the CPU has BMI1 and BMI2.
        unsafe { permute_bmi2(st, rounds) }
    } else {
        portable::permute(st, rounds);
    }
}
