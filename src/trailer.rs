//! Trailers: the few bits that say what a call is for.

use core::fmt;

/// Append a bit to an encoded trailer.
#[inline(always)]
pub(crate) const fn append_bit(encoded: u8, bit: bool) -> u8 {
    encoded + (encoded.isolate_highest_one() << bit as u8)
}

macro_rules! trailer {
    ($(#[$doc:meta])* $name:ident, $max_bits:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub(crate) u8);

        impl $name {
            /// The trailer with no bits in it.
            pub const EMPTY: Self = Self(1);
            /// The most bits a trailer can hold.
            pub const MAX_BITS: usize = $max_bits;

            /// Make a trailer from its encoding: the bits, least significant first, then a final 1.
            ///
            /// So 1 is the empty trailer, and `0b101` is a 1 bit followed by a 0 bit.
            /// Returns `None` for 0, and for more than [`MAX_BITS`](Self::MAX_BITS) bits.
            pub const fn new(encoded: u8) -> Option<Self> {
                if encoded == 0 || encoded >> Self::MAX_BITS > 1 {
                    return None;
                }
                Some(Self(encoded))
            }

            /// Make a trailer from its bits.
            ///
            /// Returns `None` for more than [`MAX_BITS`](Self::MAX_BITS) bits.
            pub const fn from_bits(bits: &[bool]) -> Option<Self> {
                if bits.len() > Self::MAX_BITS {
                    return None;
                }
                let mut encoded = 1 << bits.len();
                let mut i = 0;
                while i < bits.len() {
                    encoded |= (bits[i] as u8) << i;
                    i += 1;
                }
                Some(Self(encoded))
            }

            /// The encoding of the trailer, as taken by [`new()`](Self::new).
            pub const fn get(self) -> u8 {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::EMPTY
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({:#b})"), self.0)
            }
        }
    };
}

trailer!(
    /// Up to five bits that go with a block of an [`OverwriteDuplex`](crate::OverwriteDuplex).
    ///
    /// Blocks with different trailers give unrelated outputs, even when they hold the same bytes.
    DuplexTrailer,
    5
);
