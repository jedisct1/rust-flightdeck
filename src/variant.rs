//! The four instances: SHAKE or TurboSHAKE, at 128 or 256 bits of security.

mod sealed {
    pub trait Sealed {}
}

/// The sponge function a cipher is built on, and with it the security level.
///
/// It's one of [`TurboShake128`], [`TurboShake256`], [`Shake128`] and [`Shake256`]: this trait is sealed.
pub trait Variant: sealed::Sealed + Copy + 'static {
    #[doc(hidden)]
    const KEY_LEN: usize;
    #[doc(hidden)]
    const KEY_LEN_MAX: usize = Self::BLOCK_LEN;
    #[doc(hidden)]
    const ROUNDS: usize;
    /// The last byte of a block of the sponge function.
    #[doc(hidden)]
    const PADDING: u8;
    /// How many bytes a duplex call can absorb or return.
    #[doc(hidden)]
    const BLOCK_LEN: usize;
    /// Long inputs are cut into chunks of that many bytes.
    #[doc(hidden)]
    const CHUNK_LEN: usize;
    /// Each chunk is summed up in that many bytes.
    #[doc(hidden)]
    const CV_LEN: usize;

    /// How many lanes of the state a block takes.
    #[doc(hidden)]
    const BLOCK_LANES: usize = Self::BLOCK_LEN / 8;
    /// How many lanes of the state a chaining value takes.
    #[doc(hidden)]
    const CV_LANES: usize = Self::CV_LEN.div_ceil(8);
    /// The length of the last block of a chunk.
    #[doc(hidden)]
    const LAST_BLOCK_LEN: usize = (Self::CHUNK_LEN - 1) % Self::BLOCK_LEN + 1;

    /// The lanes after the block, once an empty key was absorbed.
    /// Hashing starts from there and saves a permutation.
    /// Empty for the instances made for the tests.
    #[doc(hidden)]
    const AFTER_EMPTY_KEY: &'static [u64] = &[];
}

/// The longest block of the four instances.
/// Buffers that hold a block are that long.
pub(crate) const MAX_BLOCK_LEN: usize = 160;

macro_rules! variant {
    (
        $(#[$doc:meta])* $name:ident, $security:literal, $rounds:literal, $padding:literal, $chunk_len:literal,
        after_empty_key: [$($lane:literal),* $(,)?]
    ) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        pub struct $name;

        impl sealed::Sealed for $name {}

        impl Variant for $name {
            const KEY_LEN: usize = $security / 8;
            const ROUNDS: usize = $rounds;
            const PADDING: u8 = $padding;
            const BLOCK_LEN: usize = 200 - 8 - $security / 4;
            const CHUNK_LEN: usize = $chunk_len;
            const CV_LEN: usize = $security / 4;
            const AFTER_EMPTY_KEY: &'static [u64] = &[$($lane),*];
        }

        const _: () = assert!($name::BLOCK_LEN <= MAX_BLOCK_LEN && $name::CV_LEN <= $name::BLOCK_LEN);
        const _: () = assert!($name::AFTER_EMPTY_KEY.len() == 25 - $name::BLOCK_LANES);
    };
}

variant!(
    /// TurboSHAKE128: 128 bits of security, 12 rounds of Keccak-p.
    TurboShake128,
    128,
    12,
    0x80,
    5120,
    after_empty_key: [
        0x4017237825f2aeaf,
        0x05fd662a978187d6,
        0xa01df91a4f6002e6,
        0x97f487c3df786970,
        0xf2c9682cca7502d6,
    ]
);
variant!(
    /// TurboSHAKE256: 256 bits of security, 12 rounds of Keccak-p.
    TurboShake256,
    256,
    12,
    0x80,
    8192,
    after_empty_key: [
        0x5ddcd29d8467a4eb,
        0xcd3efbef2f6ce29a,
        0xa8d3312d5f599c82,
        0x678b9d2f4614e912,
        0x3f21c4ca810e4712,
        0x7de321afbf58c43c,
        0x58c884507c10f30a,
        0x066fe52518bca295,
        0x40fa6b9e0b729858,
    ]
);
variant!(
    /// SHAKE128: 128 bits of security, 24 rounds of Keccak-p.
    /// About half as fast as [`TurboShake128`].
    Shake128,
    128,
    24,
    0x9f,
    5120,
    after_empty_key: [
        0x16c4be8782151ed8,
        0x3b8e07fd1d0da28e,
        0xc8292a74a7d7340c,
        0x58d772267a37dadf,
        0xa6d659450906f0ba,
    ]
);
variant!(
    /// SHAKE256: 256 bits of security, 24 rounds of Keccak-p.
    /// About half as fast as [`TurboShake256`].
    Shake256,
    256,
    24,
    0x9f,
    8192,
    after_empty_key: [
        0xb0306736a49c04d3,
        0xc1619cf5044d4bc3,
        0xee6471a45c80faaa,
        0x5b9c10dd45eb629b,
        0xd2279c1f993904a2,
        0x1ec931844d38cb09,
        0x601caf92106c782a,
        0x86dce988ca004271,
        0x593e783554a42292,
    ]
);

#[cfg(test)]
pub(crate) mod test_variants {
    use super::{Variant, sealed};

    /// Chunks that don't end on a block boundary, chaining values that don't end on a lane boundary.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct OddChunks;
    impl sealed::Sealed for OddChunks {}
    impl Variant for OddChunks {
        const KEY_LEN: usize = 16;
        const ROUNDS: usize = 12;
        const PADDING: u8 = 0x80;
        const BLOCK_LEN: usize = 160;
        const CHUNK_LEN: usize = 327;
        const CV_LEN: usize = 67;
    }

    /// The parameters of a test vector made with XKCP.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct Chunks327;
    impl sealed::Sealed for Chunks327 {}
    impl Variant for Chunks327 {
        const KEY_LEN: usize = 16;
        const ROUNDS: usize = 12;
        const PADDING: u8 = 0x80;
        const BLOCK_LEN: usize = 160;
        const CHUNK_LEN: usize = 327;
        const CV_LEN: usize = 32;
    }

    /// One block per chunk, chaining values as long as a block.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct OneBlockChunks;
    impl sealed::Sealed for OneBlockChunks {}
    impl Variant for OneBlockChunks {
        const KEY_LEN: usize = 32;
        const ROUNDS: usize = 12;
        const PADDING: u8 = 0x80;
        const BLOCK_LEN: usize = 128;
        const CHUNK_LEN: usize = 128;
        const CV_LEN: usize = 128;
    }
}
