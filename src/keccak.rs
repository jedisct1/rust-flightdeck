//! The Keccak-p[1600] permutation, on one state or on several states at once.

use core::ops::Range;

/// The same lane of `N` states, in one vector.
///
/// All of this has to be inlined into the function that was built for these vectors.
/// So no closures here: the standard library doesn't always inline the functions that take them.
pub(crate) trait Lanes<const N: usize>: Copy {
    /// Whether to write the twelve rounds out, instead of looping over a few of them.
    ///
    /// Written out is faster when there are enough registers.
    /// Otherwise it's a lot of code, and a loop does better.
    const UNROLL: bool;

    fn splat(lane: u64) -> Self;
    fn from_array(lanes: [u64; N]) -> Self;
    fn to_array(self) -> [u64; N];
    /// Read `N` lanes from the start of `bytes`.
    fn load(bytes: &[u8]) -> Self;
    /// Write `N` lanes to the start of `out`.
    fn store(self, out: &mut [u8]);
    /// Swap the rows and the columns of a square of lanes.
    ///
    /// A block has consecutive lanes of one state, a vector has the same lane of every state.
    /// This goes from one to the other.
    fn transpose(rows: [Self; N]) -> [Self; N];
    fn xor(self, other: Self) -> Self;
    /// `!self & other`
    fn and_not(self, other: Self) -> Self;
    /// Rotate left by `L` bits, 1 to 63.
    /// `R` is `64 - L`: some instruction sets need both as constants.
    fn rotl<const L: i32, const R: i32>(self) -> Self;

    /// The permutation on `N` states, like `permute_lanes()`.
    ///
    /// The caller won't read the lanes in `skip`, so they can come out as anything.
    /// A backend with faster code for the rounds puts it here.
    #[inline(always)]
    fn permute(st: &mut [Self; 25], rounds: usize, skip: Range<usize>) {
        permute_lanes(st, rounds);
        // Lets the compiler drop what the last round does for these lanes.
        st[skip].fill(Self::splat(0));
    }

    /// Like `permute()`, with one more state on general registers.
    ///
    /// Here the states take turns.
    /// A backend that runs them together puts that here, and says so with `simd::runs_one_more()`.
    #[inline(always)]
    fn permute_and_one(
        st: &mut [Self; 25],
        one: &mut [u64; 25],
        rounds: usize,
        skip: Range<usize>,
    ) {
        Self::permute(st, rounds, skip);
        crate::simd::permute(one, rounds);
    }
}

pub(crate) const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Rho and pi on one state, as (position, rotation) pairs: each lane goes to the next position, rotated.
macro_rules! rho_pi {
    ($st:ident; $(($to:literal, $bits:literal)),* $(,)?) => {
        let mut last = $st[1];
        $(
            let next = $st[$to];
            $st[$to] = last.rotate_left($bits);
            last = next;
        )*
        let _ = last;
    };
}

#[inline(always)]
fn round(st: &mut [u64; 25], round_constant: u64) {
    let mut parity = [0; 5];
    for x in 0..5 {
        parity[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
    }
    for x in 0..5 {
        let d = parity[(x + 4) % 5] ^ parity[(x + 1) % 5].rotate_left(1);
        for y in 0..5 {
            st[5 * y + x] ^= d;
        }
    }

    rho_pi!(st;
        (10, 1), (7, 3), (11, 6), (17, 10), (18, 15), (3, 21), (5, 28), (16, 36),
        (8, 45), (21, 55), (24, 2), (4, 14), (15, 27), (23, 41), (19, 56), (13, 8),
        (12, 25), (2, 43), (20, 62), (14, 18), (22, 39), (9, 61), (6, 20), (1, 44),
    );

    for y in 0..5 {
        let row = [
            st[5 * y],
            st[5 * y + 1],
            st[5 * y + 2],
            st[5 * y + 3],
            st[5 * y + 4],
        ];
        for x in 0..5 {
            st[5 * y + x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
        }
    }

    st[0] ^= round_constant;
}

/// The last `rounds` rounds of Keccak-f[1600] on one state: 12 or 24.
///
/// Call `simd::permute()` instead: this is inlined there, and built for what the CPU has.
#[inline(always)]
pub(crate) fn permute(st: &mut [u64; 25], rounds: usize) {
    debug_assert!(rounds == 12 || rounds == 24);

    // Three rounds per iteration is what measured fastest, on WebAssembly above all.
    for constants in ROUND_CONSTANTS[24 - rounds..].as_chunks::<3>().0 {
        round(st, constants[0]);
        round(st, constants[1]);
        round(st, constants[2]);
    }
}

/// Rho and pi on several states: where each lane comes from, and how far it's rotated.
macro_rules! rho_pi_lanes {
    ($a:ident; $(($from:literal, $bits:literal)),* $(,)?) => {
        [$a[0], $($a[$from].rotl::<$bits, { 64 - $bits }>()),*]
    };
}

/// One round on several states.
/// It takes the parity of the columns, and leaves the parity for the next round.
///
/// Same result as `round()`, in a shape that compilers turn into better vector code.
#[inline(always)]
fn round_lanes<L: Lanes<N>, const N: usize>(
    st: &mut [L; 25],
    parity: &mut [L; 5],
    round_constant: u64,
) {
    let mut a = *st;
    for x in 0..5 {
        let d = parity[(x + 4) % 5].xor(parity[(x + 1) % 5].rotl::<1, 63>());
        for y in 0..5 {
            a[5 * y + x] = a[5 * y + x].xor(d);
        }
    }

    let b = rho_pi_lanes!(a;
        (6, 44), (12, 43), (18, 21), (24, 14),
        (3, 28), (9, 20), (10, 3), (16, 45), (22, 61),
        (1, 1), (7, 6), (13, 25), (19, 8), (20, 18),
        (4, 27), (5, 36), (11, 10), (17, 15), (23, 56),
        (2, 62), (8, 55), (14, 39), (15, 41), (21, 2),
    );

    for y in 0..5 {
        for x in 0..5 {
            st[5 * y + x] =
                b[5 * y + x].xor(b[5 * y + (x + 1) % 5].and_not(b[5 * y + (x + 2) % 5]));
        }
    }
    st[0] = st[0].xor(L::splat(round_constant));
    *parity = column_parity(st);
}

#[inline(always)]
fn column_parity<L: Lanes<N>, const N: usize>(st: &[L; 25]) -> [L; 5] {
    let mut parity = [st[0]; 5];
    for x in 0..5 {
        parity[x] = st[x]
            .xor(st[x + 5])
            .xor(st[x + 10])
            .xor(st[x + 15])
            .xor(st[x + 20]);
    }
    parity
}

#[inline(always)]
fn four_rounds<L: Lanes<N>, const N: usize>(
    st: &mut [L; 25],
    parity: &mut [L; 5],
    constants: &[u64],
) {
    round_lanes(st, parity, constants[0]);
    round_lanes(st, parity, constants[1]);
    round_lanes(st, parity, constants[2]);
    round_lanes(st, parity, constants[3]);
}

/// The last `rounds` rounds of Keccak-f[1600] on `N` states: 12 or 24.
/// `st[i]` is lane `i` of every state.
///
/// Call `Lanes::permute()` instead: the backend may have something faster.
#[inline(always)]
pub(crate) fn permute_lanes<L: Lanes<N>, const N: usize>(st: &mut [L; 25], rounds: usize) {
    debug_assert!(rounds == 12 || rounds == 24);

    let mut parity = column_parity(st);
    let constants = &ROUND_CONSTANTS[24 - rounds..];
    if L::UNROLL {
        for constants in constants.as_chunks::<12>().0 {
            four_rounds(st, &mut parity, &constants[..4]);
            four_rounds(st, &mut parity, &constants[4..8]);
            four_rounds(st, &mut parity, &constants[8..]);
        }
    } else {
        for constants in constants.as_chunks::<4>().0 {
            four_rounds(st, &mut parity, constants);
        }
    }
}
