//! Picks the vectors used to run several states at once on the target.
//!
//! Every backend has the same three functions:
//!
//! - `parallelism()`: how many states can be processed at once, a power of two.
//! - `run()`: run a job on `n` states, a power of two from 2 to `parallelism()`.
//! - `permute()`: the permutation of one state. It's not inlined, so that all the duplex ciphers share it.

mod portable;

// Targets with vector instructions turned off, as kernels do, get the last case.
cfg_select! {
    all(target_arch = "x86_64", target_feature = "sse2") => {
        mod x86_64;
        pub(crate) use x86_64::{parallelism, permute, run};
    }
    all(target_arch = "aarch64", target_endian = "little", target_feature = "neon") => {
        mod aarch64;
        pub(crate) use aarch64::{parallelism, run};
        pub(crate) use portable::permute;
    }
    all(target_arch = "wasm32", target_feature = "simd128") => {
        mod wasm32;
        pub(crate) use portable::permute;
        pub(crate) use wasm32::{parallelism, run};
    }
    _ => {
        mod scalar;
        pub(crate) use portable::permute;
        pub(crate) use scalar::{parallelism, run};
    }
}
