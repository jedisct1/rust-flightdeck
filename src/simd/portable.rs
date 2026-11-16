//! The permutation of one state, built for what every CPU of the target has.

use crate::keccak;

#[inline(never)]
pub(crate) fn permute(st: &mut [u64; 25], rounds: usize) {
    keccak::permute(st, rounds);
}
