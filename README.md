# FlightDeck for Rust

A Rust implementation of FlightDeck and Deck-BO for encrypting and authenticating data.

It's a port of the [Zig implementation](https://github.com/jedisct1/flightdeck-deckbo), with the same three layers and the same results.

It works with and without `std`, doesn't allocate unless you ask for it, and its only dependency is `cpufeatures`, on x86-64, to find out what the CPU can do.

## What's in there

- Duplex cipher: `Shake128Duplex`, `Shake256Duplex`, `TurboShake128Duplex`, `TurboShake256Duplex`.
- Deck cipher: `Shake128FlightDeck`, `Shake256FlightDeck`, `TurboShake128FlightDeck`, `TurboShake256FlightDeck`.
- Authenticated encryption: `Shake128Bo<TAG_LEN>`, `Shake256Bo<TAG_LEN>`, `TurboShake128Bo<TAG_LEN>`, `TurboShake256Bo<TAG_LEN>`.

Not sure which layer you need? Here's what each one does:

- Authenticated encryption is what you want to protect messages.
  You give it a key and a message, and it gives you back a ciphertext nobody can read, plus a tag that proves nobody tampered with it.
  If you just want to encrypt things, pick this one and ignore the rest.
- A deck cipher is the building block underneath.
  It mixes a key with any data you feed it, and gives you back as many random-looking bytes as you ask for.
  That's handy to authenticate data without encrypting it, to derive keys, or to build your own protocol.
- A duplex cipher does the same thing as a deck cipher, but only on small blocks, one at a time.
  The deck cipher is built with it, and unless you're building a mode of your own, you won't need it directly.

These names are aliases of three generic types: `OverwriteDuplex<V>`, `FlightDeck<V>` and `DeckBo<V, TAG_LEN>`, where `V` is one of `Shake128`, `Shake256`, `TurboShake128` and `TurboShake256`.

And SHAKE or TurboSHAKE?
The TurboSHAKE instances use 12 rounds of Keccak-p[1600] and are about twice as fast as the SHAKE ones, which use 24.
The 128 and 256 in the names are the security levels, in bits.

## Installing

```toml
[dependencies]
flightdeck = { git = "https://github.com/jedisct1/rust-flightdeck" }
```

There are two features:

- `std` is on by default. For now, all it does is turn `alloc` on.
- `alloc` adds the functions that return a `Vec`.

For a `no_std` build, turn the default features off:

```toml
flightdeck = { git = "https://github.com/jedisct1/rust-flightdeck", default-features = false }
```

On x86-64, SSE2, AVX2 or AVX-512 is picked when your program runs, and AArch64 uses NEON, so there's nothing to set up.

WebAssembly is the one target where you have to ask, because a module can't check what its runtime supports.
Build with `simd128` and long messages go through about 1.7 times as fast:

```sh
RUSTFLAGS="-C target-feature=+simd128" cargo build --release --target wasm32-wasip1
```

## Usage

Authenticated encryption works on sessions: the two sides share a key, and messages are decrypted in the order they were encrypted.

```rust
use flightdeck::TurboShake128Bo;

// 16 is the length of the tags, in bytes.
let mut sender = TurboShake128Bo::<16>::new(&key)?;
let mut receiver = TurboShake128Bo::<16>::new(&key)?;

// The ciphertext, followed by the tag.
let ciphertext = sender.encrypt(associated_data, message);
let decrypted = receiver.decrypt(associated_data, &ciphertext)?;
```

Without `alloc`, or to avoid copies, do it in place:

```rust
let tag = sender.encrypt_in_place(associated_data, &mut buffer);
receiver.decrypt_in_place(associated_data, &mut buffer, &tag)?;
```

Every message is authenticated along with all the messages that came before it in the session.
If something doesn't match, you get an error, the buffer is zeroed, and the session stays where it was.

There's no nonce. So if you encrypt the same message twice, at the same point of two sessions with the same key, you get the same ciphertext.

Besides the length of the message, that's all it reveals, but if it matters to you, put a nonce or a counter in the associated data.

The tag length is a parameter, in bytes.

A tag of twice the security level, so 32 bytes for the 128-bit instances, also commits to the key, the associated data and the plaintext at that security level.

Keys are normally `KEY_LEN` random bytes: 16 for the 128-bit instances and 32 for the 256-bit ones.

That said, any byte string of at most `KEY_LEN_MAX` bytes is accepted, which is 160 and 128 bytes respectively.
Longer than that, and `new()` returns an error.

A deck cipher takes strings of any length, and gives you back as many bytes as you want after each of them.
Those bytes depend on the key and on everything it was given so far.

```rust
use flightdeck::{Trailer, TurboShake128FlightDeck};

let mut deck = TurboShake128FlightDeck::new(&key)?;

// Absorb a string, get 32 bytes that depend on the key and on that string.
let mut mac = [0; 32];
deck.duplex(message, Trailer::EMPTY, &mut mac);

// Get more output from the same call.
let mut more = [0; 1000];
deck.squeeze(&mut more);

// Absorb another string. The output now depends on both strings.
// It can also be XORed into a buffer, to use it as a keystream.
deck.duplex(nonce, Trailer::EMPTY, &mut []);
deck.xor(&mut buffer);
```

That second argument of `duplex()` is a trailer: up to four bits you can use for domain separation.
Calls with different trailers give unrelated outputs, even on the same input.

`Trailer::from_bits(&[true, false])` makes one from its bits.
`Trailer::new(0b101)` makes the same one from its encoding: the bits, least significant first, followed by a final 1.
Both return `None` when there are too many bits.

Need a clone? `clone()` does it.
There's also `clone_compact()`, which gives you a clone that can only be used to absorb the next string.

One thing to remember: call `duplex()` before `squeeze()` or `xor()`.
There's nothing to squeeze before that, and they panic.

## Running the tests

```sh
cargo test     # run the tests
cargo bench    # measure the throughput
```

To run them for WebAssembly, with [Wasmer](https://wasmer.io):

```sh
export CARGO_TARGET_WASM32_WASIP1_RUNNER="wasmer run --"
export RUSTFLAGS="-C target-feature=+simd128"
cargo test --target wasm32-wasip1
cargo bench --target wasm32-wasip1
```

## Papers

FlightDeck comes from ["Parallelizable modes for duplex-based authenticated encryption"](https://eprint.iacr.org/2026/2801) by Joan Daemen, Silvia Mella and Gilles Van Assche.

The overwrite duplex and Deck-BO come from ["Shaking up authenticated encryption"](https://eprint.iacr.org/2024/1618) by Joan Daemen, Seth Hoffert, Silvia Mella, Gilles Van Assche and Ronny Van Keer.
