//! What every target has: the permutation of one state, and no extras.

use core::ops::Range;

use crate::batch::Job;
use crate::keccak;

#[inline(never)]
pub(crate) fn permute(st: &mut [u64; 25], rounds: usize) {
    keccak::permute(st, rounds);
}

#[allow(dead_code)]
pub(crate) fn runs_one_state() -> bool {
    false
}

#[allow(dead_code)]
pub(crate) fn run_one_state<J: Job>(_job: J) -> J::Out {
    unreachable!("no vectors for a single state on this target")
}

#[allow(dead_code)]
pub(crate) fn runs_one_more(_n: usize, _rounds: usize, _skip: Range<usize>) -> bool {
    false
}
