//! Picks the vectors used to run several states at once on the target.
//!
//! Every backend has the same two functions:
//!
//! - `parallelism()`: how many states can be processed at once, a power of two.
//! - `run()`: run a job on `n` states, a power of two from 2 to `parallelism()`.

cfg_select! {
    all(target_arch = "wasm32", target_feature = "simd128") => {
        mod wasm32;
        pub(crate) use wasm32::{parallelism, run};
    }
    _ => {
        mod scalar;
        pub(crate) use scalar::{parallelism, run};
    }
}
