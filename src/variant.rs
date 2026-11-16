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
    /// The length of the last block of a chunk.
    #[doc(hidden)]
    const LAST_BLOCK_LEN: usize = (Self::CHUNK_LEN - 1) % Self::BLOCK_LEN + 1;
}

/// The longest block of the four instances.
/// Buffers that hold a block are that long.
pub(crate) const MAX_BLOCK_LEN: usize = 160;

macro_rules! variant {
    ($(#[$doc:meta])* $name:ident, $security:literal, $rounds:literal, $padding:literal, $chunk_len:literal) => {
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
        }

        const _: () = assert!($name::BLOCK_LEN <= MAX_BLOCK_LEN && $name::CV_LEN <= $name::BLOCK_LEN);
    };
}

variant!(
    /// TurboSHAKE128: 128 bits of security, 12 rounds of Keccak-p.
    TurboShake128,
    128,
    12,
    0x80,
    5120
);
variant!(
    /// TurboSHAKE256: 256 bits of security, 12 rounds of Keccak-p.
    TurboShake256,
    256,
    12,
    0x80,
    8192
);
variant!(
    /// SHAKE128: 128 bits of security, 24 rounds of Keccak-p.
    /// About half as fast as [`TurboShake128`].
    Shake128,
    128,
    24,
    0x9f,
    5120
);
variant!(
    /// SHAKE256: 256 bits of security, 24 rounds of Keccak-p.
    /// About half as fast as [`TurboShake256`].
    Shake256,
    256,
    24,
    0x9f,
    8192
);
