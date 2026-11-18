//! x86-64: two states at once with SSE2, four with AVX2, eight with AVX-512.
//!
//! This file is only built for targets with SSE2.
//! The rest is looked for when the program runs.
//!
//! AVX2 and AVX-512 are also used on fewer states, where they still beat SSE2.
//! AVX-512 means AVX-512F and AVX-512VL here: a CPU with only the first one gets the AVX2 code.

use core::arch::asm;
use core::arch::x86_64::{
    __m128i, __m256i, __m512i, _mm_andnot_si128, _mm_loadl_epi64, _mm_loadu_si128, _mm_or_si128,
    _mm_rol_epi64, _mm_slli_epi64, _mm_srli_epi64, _mm_storel_epi64, _mm_storeu_si128,
    _mm_unpackhi_epi64, _mm_unpacklo_epi64, _mm_xor_si128, _mm256_andnot_si256,
    _mm256_castsi128_si256, _mm256_castsi256_si128, _mm256_loadu_si256, _mm256_or_si256,
    _mm256_permute2x128_si256, _mm256_rol_epi64, _mm256_slli_epi64, _mm256_srli_epi64,
    _mm256_storeu_si256, _mm256_unpackhi_epi64, _mm256_unpacklo_epi64, _mm256_xor_si256,
    _mm512_andnot_si512, _mm512_loadu_si512, _mm512_rol_epi64, _mm512_shuffle_i64x2,
    _mm512_storeu_si512, _mm512_unpackhi_epi64, _mm512_unpacklo_epi64, _mm512_xor_si512,
};
use core::mem::MaybeUninit;
use core::ops::Range;

use crate::batch::Job;
use crate::keccak::{self, Lanes};
use crate::simd::portable;

cpufeatures::new!(avx2, "avx2");
cpufeatures::new!(avx512, "avx512f", "avx512vl", "bmi1", "bmi2");
cpufeatures::new!(bmi2, "bmi1", "bmi2");

/// The best vector instructions the CPU has.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Tier {
    Sse2,
    Avx2,
    Avx512,
}

fn tier() -> Tier {
    // Building with `--cfg flightdeck_no_avx512` keeps AVX-512 out:
    // that's how to measure the AVX2 code on a CPU that has both.
    let tier = if cfg!(not(flightdeck_no_avx512)) && avx512::get() {
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
        $(permute: $permute:ident,)?
        $(permute_and_one: $permute_and_one:ident,)?
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

            $(
                #[inline(always)]
                fn permute(st: &mut [Self; 25], rounds: usize, skip: Range<usize>) {
                    unsafe { $permute(st, rounds, skip) }
                }
            )?

            $(
                #[inline(always)]
                fn permute_and_one(
                    st: &mut [Self; 25],
                    one: &mut [u64; 25],
                    rounds: usize,
                    skip: Range<usize>,
                ) {
                    unsafe { $permute_and_one(st, one, rounds, skip) }
                }
            )?
        }
    };
}

lanes!(
    /// Two states.
    /// The kernels built for AVX2 use it too, and get better instructions out of the same code.
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
    permute: permute_x4_avx2,
);

lanes!(
    /// Like `Avx2`, with the rounds in assembly for AVX-512.
    Avx512x4: 4 lanes in __m256i,
    unroll: true,
    load: _mm256_loadu_si256,
    store: _mm256_storeu_si256,
    xor: _mm256_xor_si256,
    and_not: _mm256_andnot_si256,
    rotl: |x| _mm256_rol_epi64::<L>(x),
    transpose: transpose_256(a, b, c, d),
    permute: permute_x4,
);

lanes!(
    /// One state, in the low part of the registers: it goes through the rounds for four.
    Avx512x1: 1 lanes in __m128i,
    unroll: true,
    load: _mm_loadl_epi64,
    store: _mm_storel_epi64,
    xor: _mm_xor_si128,
    and_not: _mm_andnot_si128,
    rotl: |x| _mm_rol_epi64::<L>(x),
    transpose: transpose_64(a),
    permute: permute_x1,
);

lanes!(
    /// Like `Sse2`, with the rounds in assembly for AVX-512.
    Avx512x2: 2 lanes in __m128i,
    unroll: true,
    load: _mm_loadu_si128,
    store: _mm_storeu_si128,
    xor: _mm_xor_si128,
    and_not: _mm_andnot_si128,
    rotl: |x| _mm_rol_epi64::<L>(x),
    transpose: transpose_128(a, b),
    permute: permute_x2,
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
    permute: permute_x8,
    permute_and_one: permute_x8_and_one,
);

/// Runs assembly on the 25 vectors of `$st`: lane `i` is in register `i`, and `rax` points to the round constants.
/// The seven registers left are scratch. `$width` is `zmm`, `ymm` or `xmm`.
macro_rules! in_registers {
    (zmm, $($rest:tt)*) => {
        in_registers!(
            @run
            [
                "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7", "zmm8", "zmm9",
                "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15", "zmm16", "zmm17", "zmm18",
                "zmm19", "zmm20", "zmm21", "zmm22", "zmm23", "zmm24"
            ],
            ["zmm25", "zmm26", "zmm27", "zmm28", "zmm29", "zmm30", "zmm31"],
            $($rest)*
        )
    };
    (ymm, $($rest:tt)*) => {
        in_registers!(
            @run
            [
                "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9",
                "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15", "ymm16", "ymm17", "ymm18",
                "ymm19", "ymm20", "ymm21", "ymm22", "ymm23", "ymm24"
            ],
            ["ymm25", "ymm26", "ymm27", "ymm28", "ymm29", "ymm30", "ymm31"],
            $($rest)*
        )
    };
    (xmm, $($rest:tt)*) => {
        in_registers!(
            @run
            [
                "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
                "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "xmm16", "xmm17", "xmm18",
                "xmm19", "xmm20", "xmm21", "xmm22", "xmm23", "xmm24"
            ],
            ["xmm25", "xmm26", "xmm27", "xmm28", "xmm29", "xmm30", "xmm31"],
            $($rest)*
        )
    };
    (
        @run
        [
            $r0:tt, $r1:tt, $r2:tt, $r3:tt, $r4:tt, $r5:tt, $r6:tt, $r7:tt, $r8:tt, $r9:tt, $r10:tt,
            $r11:tt, $r12:tt, $r13:tt, $r14:tt, $r15:tt, $r16:tt, $r17:tt, $r18:tt, $r19:tt, $r20:tt,
            $r21:tt, $r22:tt, $r23:tt, $r24:tt
        ],
        [$($scratch:tt),*],
        $st:ident: $lanes:ident, $constants:ident,
        asm($($template:tt)*),
        options($($option:ident),*)
    ) => {{
        let [
            mut s0, mut s1, mut s2, mut s3, mut s4, mut s5, mut s6, mut s7, mut s8, mut s9,
            mut s10, mut s11, mut s12, mut s13, mut s14, mut s15, mut s16, mut s17, mut s18,
            mut s19, mut s20, mut s21, mut s22, mut s23, mut s24,
        ] = $st.map(|lanes| lanes.0);
        // SAFETY: the assembly only reads the constants, and only writes to the registers listed here.
        unsafe {
            asm!(
                $($template)*,
                in("rax") $constants.as_ptr(),
                inout($r0) s0, inout($r1) s1, inout($r2) s2, inout($r3) s3, inout($r4) s4,
                inout($r5) s5, inout($r6) s6, inout($r7) s7, inout($r8) s8, inout($r9) s9,
                inout($r10) s10, inout($r11) s11, inout($r12) s12, inout($r13) s13,
                inout($r14) s14, inout($r15) s15, inout($r16) s16, inout($r17) s17,
                inout($r18) s18, inout($r19) s19, inout($r20) s20, inout($r21) s21,
                inout($r22) s22, inout($r23) s23, inout($r24) s24,
                $(out($scratch) _,)*
                options($($option),*),
            );
        }
        *$st = [
            s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18,
            s19, s20, s21, s22, s23, s24,
        ]
        .map($lanes);
    }};
}

/// Twelve rounds on eight states, with the assembly of a file.
macro_rules! twelve_rounds_x8 {
    ($name:ident: $file:literal) => {
        #[target_feature(enable = "avx512f,avx512vl")]
        #[inline]
        fn $name(st: &mut [Avx512; 25], constants: &[u64; 12]) {
            in_registers!(
                zmm,
                st: Avx512,
                constants,
                asm(include_str!($file)),
                options(pure, readonly, nostack, preserves_flags)
            );
        }
    };
}

twelve_rounds_x8!(twelve_rounds_x8: "keccak_avx512_x8.s");
twelve_rounds_x8!(twelve_rounds_x8_skip16: "keccak_avx512_x8_skip16.s");
twelve_rounds_x8!(twelve_rounds_x8_skip20: "keccak_avx512_x8_skip20.s");

/// Keccak-p[1600] on eight states, in assembly.
///
/// The compiler has the same instructions, but lays them out in a way that runs slower.
/// `tools/keccak_x86.py` writes the assembly and explains what matters.
///
/// Nothing can be dropped from assembly, so the two usual values of `skip` have a file of their own.
///
/// # Safety
///
/// The CPU has AVX-512F and AVX-512VL.
#[inline(always)]
unsafe fn permute_x8(st: &mut [Avx512; 25], rounds: usize, skip: Range<usize>) {
    debug_assert!(rounds == 12 || rounds == 24);

    let constants = keccak::ROUND_CONSTANTS[24 - rounds..].as_chunks::<12>().0;
    let (last, first) = constants.split_last().unwrap();
    // SAFETY: the caller checked.
    unsafe {
        for constants in first {
            twelve_rounds_x8(st, constants);
        }
        match (skip.start, skip.end) {
            (0, 20) => twelve_rounds_x8_skip20(st, last),
            (0, 16) => twelve_rounds_x8_skip16(st, last),
            _ => twelve_rounds_x8(st, last),
        }
    }
}

/// Twelve rounds on eight states in vectors and on a ninth one on general registers.
/// Only lanes 0 to 3 and 20 to 24 of the results are right.
///
/// The two kinds of instructions run on different parts of the CPU, so the ninth state is cheap.
/// This is a routine for `twelve_rounds_x9()` to call, not a Rust function.
/// The file says which registers it uses.
#[unsafe(naked)]
unsafe extern "C" fn twelve_rounds_nine() {
    core::arch::naked_asm!(include_str!("keccak_avx512_x9_block20.s"), "ret")
}

#[target_feature(enable = "avx512f,avx512vl")]
#[inline]
fn twelve_rounds_x9(st: &mut [Avx512; 25], one: &mut [u64; 25], constants: &[u64; 12]) {
    let mut scratch = [MaybeUninit::<u64>::uninit(); 25];
    in_registers!(
        zmm,
        st: Avx512,
        constants,
        asm(
            "call {rounds}",
            rounds = sym twelve_rounds_nine,
            in("rdi") one.as_mut_ptr(),
            in("rsi") scratch.as_mut_ptr(),
            out("rcx") _, out("rdx") _, out("r8") _, out("r9") _, out("r10") _,
            out("r11") _, out("r12") _, out("r13") _, out("r14") _, out("r15") _
        ),
        options()
    );
}

/// Whether `twelve_rounds_nine()` computes everything outside of `skip`.
///
/// That's TurboSHAKE128 absorbing a block.
/// A ninth state made the other instances slower.
const fn nine_states(rounds: usize, skip: &Range<usize>) -> bool {
    rounds == 12 && skip.start <= 4 && skip.end >= 20
}

/// Keccak-p[1600] on eight states in vectors and one on general registers.
///
/// # Safety
///
/// The CPU has AVX-512F, AVX-512VL, BMI1 and BMI2.
#[inline(always)]
unsafe fn permute_x8_and_one(
    st: &mut [Avx512; 25],
    one: &mut [u64; 25],
    rounds: usize,
    skip: Range<usize>,
) {
    // SAFETY: the caller checked.
    unsafe {
        if nine_states(rounds, &skip) {
            twelve_rounds_x9(st, one, keccak::ROUND_CONSTANTS.last_chunk().unwrap());
        } else {
            // Only the tests get here.
            permute_x8(st, rounds, skip);
            permute_avx512(one, rounds);
        }
    }
}

/// Twelve rounds on four states, lane `i` in `ymm<i>` and the round constants at `rax`.
/// This is a routine for assembly to call, not a Rust function.
///
/// One, two and four states all share this one copy, and nothing is skipped.
/// In these registers the rounds are so fast that the CPU struggles to fetch the instructions,
/// and a second copy taking turns with the first one makes that a lot worse.
#[unsafe(naked)]
unsafe extern "C" fn twelve_rounds_ymm() {
    core::arch::naked_asm!(include_str!("keccak_avx512_x4.s"), "ret")
}

/// Makes `$permute`, the `Lanes::permute()` of `$lanes`, out of the rounds in `$routine`.
macro_rules! permute_with_routine {
    ($permute:ident, $twelve:ident: $lanes:ident in $width:ident, $routine:ident) => {
        #[target_feature(enable = "avx512f,avx512vl")]
        #[inline]
        fn $twelve(st: &mut [$lanes; 25], constants: &[u64; 12]) {
            in_registers!(
                $width,
                st: $lanes,
                constants,
                asm("call {rounds}", rounds = sym $routine),
                options(pure, readonly, preserves_flags)
            );
        }

        /// # Safety
        ///
        /// The CPU has AVX-512F and AVX-512VL.
        #[inline(always)]
        unsafe fn $permute(st: &mut [$lanes; 25], rounds: usize, _skip: Range<usize>) {
            debug_assert!(rounds == 12 || rounds == 24);

            for constants in keccak::ROUND_CONSTANTS[24 - rounds..].as_chunks::<12>().0 {
                // SAFETY: the caller checked.
                unsafe { $twelve(st, constants) };
            }
        }
    };
}

/// Like `permute_with_routine!`, for lanes in `xmm` registers that go through the rounds for four states.
///
/// A `ymm` instruction costs what an `xmm` one does on the CPUs measured.
/// One copy of the rounds for one, two and four states stays in the cache of decoded instructions,
/// where two copies taking turns, the output of a deck right after a duplex call for instance, could slow down by half.
macro_rules! permute_in_ymm {
    ($permute:ident, $twelve:ident: $lanes:ident) => {
        #[target_feature(enable = "avx512f,avx512vl")]
        #[inline]
        fn $twelve(st: &mut [$lanes; 25], constants: &[u64; 12]) {
            // The upper halves are whatever was there: lanes don't mix in the rounds.
            let mut lanes = st.map(|lanes| Avx512x4(_mm256_castsi128_si256(lanes.0)));
            let wide = &mut lanes;
            in_registers!(
                ymm,
                wide: Avx512x4,
                constants,
                asm("call {rounds}", rounds = sym twelve_rounds_ymm),
                options(pure, readonly, preserves_flags)
            );
            *st = lanes.map(|lanes| $lanes(_mm256_castsi256_si128(lanes.0)));
        }

        /// # Safety
        ///
        /// The CPU has AVX-512F and AVX-512VL.
        #[inline(always)]
        unsafe fn $permute(st: &mut [$lanes; 25], rounds: usize, _skip: Range<usize>) {
            debug_assert!(rounds == 12 || rounds == 24);

            for constants in keccak::ROUND_CONSTANTS[24 - rounds..].as_chunks::<12>().0 {
                // SAFETY: the caller checked.
                unsafe { $twelve(st, constants) };
            }
        }
    };
}

permute_with_routine!(permute_x4, twelve_rounds_x4: Avx512x4 in ymm, twelve_rounds_ymm);
permute_in_ymm!(permute_x2, twelve_rounds_x2: Avx512x2);
permute_in_ymm!(permute_x1, twelve_rounds_x1: Avx512x1);

/// What the AVX2 rounds read: the byte shuffles that rotate lanes by 8 and by 56 bits,
/// then twelve round constants, four times each.
#[repr(C, align(32))]
struct Avx2Constants([[u64; 4]; 14]);

const fn avx2_constants(first_round: usize) -> Avx2Constants {
    let mut table = [[0; 4]; 14];
    table[0] = [
        0x0605040302010007,
        0x0e0d0c0b0a09080f,
        0x0605040302010007,
        0x0e0d0c0b0a09080f,
    ];
    table[1] = [
        0x0007060504030201,
        0x080f0e0d0c0b0a09,
        0x0007060504030201,
        0x080f0e0d0c0b0a09,
    ];
    let mut round = 0;
    while round < 12 {
        table[2 + round] = [keccak::ROUND_CONSTANTS[first_round + round]; 4];
        round += 1;
    }
    Avx2Constants(table)
}

static AVX2_CONSTANTS: [Avx2Constants; 2] = [avx2_constants(0), avx2_constants(12)];

/// Twelve rounds on four states with AVX2: the lanes at `rdi`, room for as many at `rsi`, the constants at `rax`.
/// `ecx` says how many rows of the result are wanted, counted from the last one: 1, 2 or 5.
/// This is a routine for assembly to call, not a Rust function.
///
/// With 16 registers the states live in memory.
/// The compiler moves them in and out much more than the rounds need.
#[unsafe(naked)]
unsafe extern "C" fn twelve_rounds_avx2() {
    core::arch::naked_asm!(include_str!("keccak_avx2_x4.s"), "ret")
}

#[target_feature(enable = "avx2")]
#[inline]
fn twelve_rounds_x4_avx2(st: &mut [Avx2; 25], constants: &Avx2Constants, rows: u32) {
    let mut scratch = [MaybeUninit::<__m256i>::uninit(); 25];
    // SAFETY: the assembly reads and writes the lanes, writes to `scratch` before it reads it,
    // reads the constants, and only changes the registers listed here.
    unsafe {
        asm!(
            "call {rounds}",
            rounds = sym twelve_rounds_avx2,
            in("rdi") st.as_mut_ptr(),
            in("rsi") scratch.as_mut_ptr(),
            in("rax") constants,
            in("ecx") rows,
            out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _,
            out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
            out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _,
            out("ymm12") _, out("ymm13") _, out("ymm14") _, out("ymm15") _,
        );
    }
}

/// Keccak-p[1600] on four states with AVX2, in assembly.
///
/// # Safety
///
/// The CPU has AVX2.
#[inline(always)]
unsafe fn permute_x4_avx2(st: &mut [Avx2; 25], rounds: usize, skip: Range<usize>) {
    debug_assert!(rounds == 12 || rounds == 24);

    // How many rows of the result hold a lane the caller reads.
    let rows = match (skip.start, skip.end) {
        (0, 20) => 1,
        (0, 16) => 2,
        _ => 5,
    };
    let (last, first) = AVX2_CONSTANTS[2 - rounds / 12..].split_last().unwrap();
    // SAFETY: the caller checked.
    unsafe {
        for constants in first {
            twelve_rounds_x4_avx2(st, constants, 5);
        }
        twelve_rounds_x4_avx2(st, last, rows);
    }
}

#[inline(always)]
unsafe fn transpose_64(lanes: [__m128i; 1]) -> [__m128i; 1] {
    lanes
}

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
        // Each half of the result only needs half of these,
        // so the compiler drops the others when the caller reads just one half.
        let abcd_02 = _mm512_shuffle_i64x2::<0x44>(ab_even, cd_even);
        let abcd_13 = _mm512_shuffle_i64x2::<0x44>(ab_odd, cd_odd);
        let efgh_02 = _mm512_shuffle_i64x2::<0x44>(ef_even, gh_even);
        let efgh_13 = _mm512_shuffle_i64x2::<0x44>(ef_odd, gh_odd);
        let abcd_46 = _mm512_shuffle_i64x2::<0xee>(ab_even, cd_even);
        let abcd_57 = _mm512_shuffle_i64x2::<0xee>(ab_odd, cd_odd);
        let efgh_46 = _mm512_shuffle_i64x2::<0xee>(ef_even, gh_even);
        let efgh_57 = _mm512_shuffle_i64x2::<0xee>(ef_odd, gh_odd);

        [
            _mm512_shuffle_i64x2::<0x88>(abcd_02, efgh_02),
            _mm512_shuffle_i64x2::<0x88>(abcd_13, efgh_13),
            _mm512_shuffle_i64x2::<0xdd>(abcd_02, efgh_02),
            _mm512_shuffle_i64x2::<0xdd>(abcd_13, efgh_13),
            _mm512_shuffle_i64x2::<0x88>(abcd_46, efgh_46),
            _mm512_shuffle_i64x2::<0x88>(abcd_57, efgh_57),
            _mm512_shuffle_i64x2::<0xdd>(abcd_46, efgh_46),
            _mm512_shuffle_i64x2::<0xdd>(abcd_57, efgh_57),
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

/// Whether a job on `n` states can take one more along, on general registers.
pub(crate) fn runs_one_more(n: usize, rounds: usize, skip: Range<usize>) -> bool {
    n == 8 && nine_states(rounds, &skip) && tier() == Tier::Avx512
}

/// With AVX-512, a single state is faster in vector registers than on general ones.
pub(crate) fn runs_one_state() -> bool {
    tier() == Tier::Avx512
}

/// Run a job on one state. Only where `runs_one_state()` says so.
pub(crate) fn run_one_state<J: Job>(job: J) -> J::Out {
    debug_assert!(runs_one_state());
    // SAFETY: the caller checked, with `runs_one_state()`.
    unsafe { run_avx512::<J, Avx512x1, 1>(job) }
}

pub(crate) fn run<J: Job>(n: usize, job: J) -> J::Out {
    // SAFETY: `tier()` says that the CPU has what the function was built for.
    match (tier(), n) {
        (Tier::Avx512, 8) => unsafe { run_avx512::<J, Avx512, 8>(job) },
        (Tier::Avx512, 4) => unsafe { run_avx512::<J, Avx512x4, 4>(job) },
        (Tier::Avx512, 2) => unsafe { run_avx512::<J, Avx512x2, 2>(job) },
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

/// The permutation of one state, in vector registers.
#[target_feature(enable = "avx512f,avx512vl")]
fn permute_avx512(st: &mut [u64; 25], rounds: usize) {
    let mut lanes = st.map(|lane| Avx512x1::from_array([lane]));
    Avx512x1::permute(&mut lanes, rounds, 0..0);
    *st = lanes.map(|lanes| lanes.to_array()[0]);
}

pub(crate) fn permute(st: &mut [u64; 25], rounds: usize) {
    if tier() == Tier::Avx512 {
        // SAFETY: the CPU has AVX-512F and AVX-512VL.
        unsafe { permute_avx512(st, rounds) }
        return;
    }

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
