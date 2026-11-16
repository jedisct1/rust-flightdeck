//! The Keccak-p[1600] permutation.

const ROUND_CONSTANTS: [u64; 24] = [
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

/// Rho and pi, as (position, rotation) pairs: each lane goes to the next position, rotated.
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

/// The last `rounds` rounds of Keccak-f[1600]: 12 or 24.
///
/// Not inlined, so that all the duplex ciphers share it.
#[inline(never)]
pub(crate) fn permute(st: &mut [u64; 25], rounds: usize) {
    debug_assert!(rounds == 12 || rounds == 24);

    // Three rounds per iteration is what measured fastest, on WebAssembly above all.
    for constants in ROUND_CONSTANTS[24 - rounds..].as_chunks::<3>().0 {
        round(st, constants[0]);
        round(st, constants[1]);
        round(st, constants[2]);
    }
}
