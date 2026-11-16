//! No vectors: one state at a time.

use crate::batch::Job;

pub(crate) fn parallelism() -> usize {
    1
}

pub(crate) fn run<J: Job>(_n: usize, _job: J) -> J::Out {
    unreachable!("no vectors on this target")
}
